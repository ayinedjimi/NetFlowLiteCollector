/*******************************************************************************
 * NetFlowLiteCollector - Collecteur léger de données NetFlow/sFlow
 *
 * Développé par: Ayi NEDJIMI Consultants
 * Date: 2025
 *
 * Description:
 *   Reçoit des datagrammes NetFlow/sFlow UDP et affiche les top talkers.
 *   Version lightweight pour analyse court terme du trafic réseau.
 *
 * AVERTISSEMENT LEGAL:
 *   Cet outil est fourni UNIQUEMENT pour des environnements LAB-CONTROLLED.
 *   L'utilisation sur des systèmes non autorisés est STRICTEMENT INTERDITE.
 *   L'utilisateur assume l'entière responsabilité légale de l'usage de ce logiciel.
 *
 ******************************************************************************/

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <sstream>
#include <ctime>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// IDs des contrôles
#define IDC_LISTVIEW        1001
#define IDC_EDIT_PORT       1002
#define IDC_BTN_START       1003
#define IDC_BTN_STOP        1004
#define IDC_BTN_EXPORT      1005
#define IDC_STATUSBAR       1006

// Structure pour un flow agrégé
struct FlowRecord {
    std::string srcIP;
    std::string dstIP;
    uint64_t packets;
    uint64_t bytes;
    uint8_t protocol;
    time_t firstSeen;
    time_t lastSeen;
};

// Clé pour l'agrégation des flows
struct FlowKey {
    std::string srcIP;
    std::string dstIP;
    uint8_t protocol;

    bool operator<(const FlowKey& other) const {
        if (srcIP != other.srcIP) return srcIP < other.srcIP;
        if (dstIP != other.dstIP) return dstIP < other.dstIP;
        return protocol < other.protocol;
    }
};

// Variables globales
HWND g_hMainWindow = nullptr;
HWND g_hListView = nullptr;
HWND g_hEditPort = nullptr;
HWND g_hStatusBar = nullptr;
std::atomic<bool> g_isListening(false);
SOCKET g_socket = INVALID_SOCKET;
std::map<FlowKey, FlowRecord> g_flows;
std::wstring g_logPath;
CRITICAL_SECTION g_flowsLock;

// Fonction de logging
void LogMessage(const std::wstring& message) {
    std::wofstream logFile(g_logPath, std::ios::app);
    if (logFile.is_open()) {
        time_t now = time(nullptr);
        wchar_t timeStr[64];
        struct tm timeInfo;
        localtime_s(&timeInfo, &now);
        wcsftime(timeStr, sizeof(timeStr) / sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &timeInfo);
        logFile << L"[" << timeStr << L"] " << message << std::endl;
    }
}

// Fonction pour obtenir le chemin de log
std::wstring GetLogPath() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logPath = tempPath;
    logPath += L"WinTools_NetFlowLiteCollector_log.txt";
    return logPath;
}

// Mettre à jour la barre de statut
void UpdateStatus(const std::wstring& status) {
    if (g_hStatusBar) {
        SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)status.c_str());
    }
    LogMessage(status);
}

// Convertir IP uint32 vers string (big endian)
std::string IPToString(uint32_t ip) {
    char buffer[16];
    sprintf_s(buffer, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
    return std::string(buffer);
}

// Convertir uint32 big endian vers host byte order
uint32_t ntohl_custom(uint32_t netlong) {
    return ((netlong & 0x000000FF) << 24) |
           ((netlong & 0x0000FF00) << 8) |
           ((netlong & 0x00FF0000) >> 8) |
           ((netlong & 0xFF000000) >> 24);
}

// Convertir uint16 big endian vers host byte order
uint16_t ntohs_custom(uint16_t netshort) {
    return ((netshort & 0x00FF) << 8) |
           ((netshort & 0xFF00) >> 8);
}

// Convertir protocole en string
std::string ProtocolToString(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        default: {
            char buffer[16];
            sprintf_s(buffer, "Proto %u", protocol);
            return std::string(buffer);
        }
    }
}

// Parser NetFlow v5
void ParseNetFlowV5(const char* data, size_t length) {
    if (length < 24) return; // Header minimum

    // NetFlow v5 Header (24 bytes)
    uint16_t version = ntohs_custom(*reinterpret_cast<const uint16_t*>(data));
    uint16_t count = ntohs_custom(*reinterpret_cast<const uint16_t*>(data + 2));

    if (version != 5) return;
    if (count == 0 || count > 30) return; // Max 30 flows par paquet v5

    // Flows records start at offset 24
    const char* flowData = data + 24;
    size_t flowSize = 48; // NetFlow v5 flow record size

    for (uint16_t i = 0; i < count && (24 + i * flowSize + flowSize) <= length; i++) {
        const char* flow = flowData + (i * flowSize);

        // Parser les champs NetFlow v5
        uint32_t srcAddr = *reinterpret_cast<const uint32_t*>(flow + 0);
        uint32_t dstAddr = *reinterpret_cast<const uint32_t*>(flow + 4);
        uint32_t dPkts = ntohl_custom(*reinterpret_cast<const uint32_t*>(flow + 16));
        uint32_t dOctets = ntohl_custom(*reinterpret_cast<const uint32_t*>(flow + 20));
        uint8_t prot = *reinterpret_cast<const uint8_t*>(flow + 38);

        // Créer la clé de flow
        FlowKey key;
        key.srcIP = IPToString(srcAddr);
        key.dstIP = IPToString(dstAddr);
        key.protocol = prot;

        // Agréger dans la map
        EnterCriticalSection(&g_flowsLock);

        auto it = g_flows.find(key);
        if (it != g_flows.end()) {
            // Flow existant - mettre à jour
            it->second.packets += dPkts;
            it->second.bytes += dOctets;
            it->second.lastSeen = time(nullptr);
        } else {
            // Nouveau flow
            FlowRecord record;
            record.srcIP = key.srcIP;
            record.dstIP = key.dstIP;
            record.packets = dPkts;
            record.bytes = dOctets;
            record.protocol = key.protocol;
            record.firstSeen = time(nullptr);
            record.lastSeen = time(nullptr);
            g_flows[key] = record;
        }

        LeaveCriticalSection(&g_flowsLock);
    }
}

// Parser NetFlow v9 (simplifié - header seulement pour détection)
void ParseNetFlowV9(const char* data, size_t length) {
    if (length < 20) return; // Header minimum

    uint16_t version = ntohs_custom(*reinterpret_cast<const uint16_t*>(data));
    uint16_t count = ntohs_custom(*reinterpret_cast<const uint16_t*>(data + 2));

    if (version != 9) return;

    // NetFlow v9 utilise des templates - parsing complexe
    // Pour lightweight collector, on log juste la réception
    std::wstringstream msg;
    msg << L"NetFlow v9 reçu: " << count << L" flowsets";
    LogMessage(msg.str());
}

// Rafraîchir la ListView
void RefreshListView() {
    if (!g_hListView) return;

    // Vider la liste
    ListView_DeleteAllItems(g_hListView);

    // Copier les flows et trier par bytes décroissant
    EnterCriticalSection(&g_flowsLock);
    std::vector<FlowRecord> sortedFlows;
    for (const auto& pair : g_flows) {
        sortedFlows.push_back(pair.second);
    }
    LeaveCriticalSection(&g_flowsLock);

    std::sort(sortedFlows.begin(), sortedFlows.end(),
             [](const FlowRecord& a, const FlowRecord& b) {
                 return a.bytes > b.bytes;
             });

    // Ajouter à la ListView (top 1000)
    int maxItems = min(1000, static_cast<int>(sortedFlows.size()));
    for (int i = 0; i < maxItems; i++) {
        const auto& flow = sortedFlows[i];

        LVITEMA lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;

        // SrcIP
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<char*>(flow.srcIP.c_str());
        int index = ListView_InsertItem(g_hListView, &lvi);

        // DstIP
        ListView_SetItemTextA(g_hListView, index, 1, const_cast<char*>(flow.dstIP.c_str()));

        // Packets
        char buffer[64];
        sprintf_s(buffer, "%llu", flow.packets);
        ListView_SetItemTextA(g_hListView, index, 2, buffer);

        // Bytes
        sprintf_s(buffer, "%llu", flow.bytes);
        ListView_SetItemTextA(g_hListView, index, 3, buffer);

        // Protocol
        std::string protStr = ProtocolToString(flow.protocol);
        ListView_SetItemTextA(g_hListView, index, 4, const_cast<char*>(protStr.c_str()));

        // FirstSeen
        struct tm firstTm;
        localtime_s(&firstTm, &flow.firstSeen);
        strftime(buffer, sizeof(buffer), "%H:%M:%S", &firstTm);
        ListView_SetItemTextA(g_hListView, index, 5, buffer);

        // LastSeen
        struct tm lastTm;
        localtime_s(&lastTm, &flow.lastSeen);
        strftime(buffer, sizeof(buffer), "%H:%M:%S", &lastTm);
        ListView_SetItemTextA(g_hListView, index, 6, buffer);
    }

    // Mettre à jour le statut
    std::wstringstream status;
    status << L"En écoute. " << g_flows.size() << L" flows uniques agrégés. Top " << maxItems << L" affichés.";
    UpdateStatus(status.str());
}

// Thread de réception NetFlow
void ListenerThread(int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        UpdateStatus(L"Erreur WSAStartup");
        g_isListening = false;
        EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_START), TRUE);
        EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_STOP), FALSE);
        return;
    }

    // Créer socket UDP
    g_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_socket == INVALID_SOCKET) {
        UpdateStatus(L"Erreur création socket");
        WSACleanup();
        g_isListening = false;
        EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_START), TRUE);
        EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_STOP), FALSE);
        return;
    }

    // Bind
    sockaddr_in serverAddr = { 0 };
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(static_cast<u_short>(port));

    if (bind(g_socket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::wstringstream msg;
        msg << L"Erreur bind port " << port << L" (port déjà utilisé?)";
        UpdateStatus(msg.str());
        closesocket(g_socket);
        WSACleanup();
        g_isListening = false;
        EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_START), TRUE);
        EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_STOP), FALSE);
        return;
    }

    std::wstringstream msg;
    msg << L"En écoute sur port UDP " << port;
    UpdateStatus(msg.str());

    // Timeout de 1 seconde pour permettre l'arrêt propre
    DWORD timeout = 1000;
    setsockopt(g_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    char buffer[8192];
    sockaddr_in clientAddr;
    int clientAddrLen = sizeof(clientAddr);

    DWORD lastRefresh = GetTickCount();

    while (g_isListening) {
        int bytesReceived = recvfrom(g_socket, buffer, sizeof(buffer), 0,
                                    (struct sockaddr*)&clientAddr, &clientAddrLen);

        if (bytesReceived > 0) {
            // Détecter la version NetFlow
            if (bytesReceived >= 2) {
                uint16_t version = ntohs_custom(*reinterpret_cast<uint16_t*>(buffer));

                if (version == 5) {
                    ParseNetFlowV5(buffer, bytesReceived);
                } else if (version == 9 || version == 10) {
                    ParseNetFlowV9(buffer, bytesReceived);
                }
            }

            // Rafraîchir la ListView toutes les 2 secondes
            DWORD now = GetTickCount();
            if (now - lastRefresh > 2000) {
                RefreshListView();
                lastRefresh = now;
            }
        } else if (bytesReceived == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err != WSAETIMEDOUT) {
                // Erreur réelle
                break;
            }
        }
    }

    // Dernier rafraîchissement
    RefreshListView();

    closesocket(g_socket);
    WSACleanup();

    UpdateStatus(L"Écoute arrêtée");
    EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_START), TRUE);
    EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_STOP), FALSE);
}

// Démarrer l'écoute
void StartListener() {
    if (g_isListening) return;

    wchar_t portStr[16];
    GetWindowTextW(g_hEditPort, portStr, 16);
    int port = _wtoi(portStr);

    if (port <= 0 || port > 65535) {
        MessageBoxW(g_hMainWindow, L"Port invalide (1-65535)", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    // Nettoyer les flows précédents
    EnterCriticalSection(&g_flowsLock);
    g_flows.clear();
    LeaveCriticalSection(&g_flowsLock);
    ListView_DeleteAllItems(g_hListView);

    g_isListening = true;
    EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_START), FALSE);
    EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_STOP), TRUE);

    std::thread(ListenerThread, port).detach();
}

// Arrêter l'écoute
void StopListener() {
    if (!g_isListening) return;
    g_isListening = false;
    UpdateStatus(L"Arrêt en cours...");
}

// Exporter vers CSV
void ExportToCSV() {
    wchar_t fileName[MAX_PATH] = L"NetFlowLiteCollector_Export.csv";
    OPENFILENAMEW ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWindow;
    ofn.lpstrFilter = L"Fichiers CSV (*.csv)\0*.csv\0Tous les fichiers (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Exporter les flows NetFlow";
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"csv";

    if (GetSaveFileNameW(&ofn)) {
        std::ofstream csvFile(fileName, std::ios::binary | std::ios::trunc);
        if (csvFile.is_open()) {
            // BOM UTF-8
            const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
            csvFile.write(reinterpret_cast<const char*>(bom), sizeof(bom));

            // Header
            csvFile << "SrcIP,DstIP,Packets,Bytes,Protocol,FirstSeen,LastSeen\n";

            // Copier et trier les flows
            EnterCriticalSection(&g_flowsLock);
            std::vector<FlowRecord> sortedFlows;
            for (const auto& pair : g_flows) {
                sortedFlows.push_back(pair.second);
            }
            LeaveCriticalSection(&g_flowsLock);

            std::sort(sortedFlows.begin(), sortedFlows.end(),
                     [](const FlowRecord& a, const FlowRecord& b) {
                         return a.bytes > b.bytes;
                     });

            // Écrire les données
            for (const auto& flow : sortedFlows) {
                char firstSeenStr[32], lastSeenStr[32];
                struct tm firstTm, lastTm;
                localtime_s(&firstTm, &flow.firstSeen);
                localtime_s(&lastTm, &flow.lastSeen);
                strftime(firstSeenStr, sizeof(firstSeenStr), "%Y-%m-%d %H:%M:%S", &firstTm);
                strftime(lastSeenStr, sizeof(lastSeenStr), "%Y-%m-%d %H:%M:%S", &lastTm);

                csvFile << flow.srcIP << ","
                       << flow.dstIP << ","
                       << flow.packets << ","
                       << flow.bytes << ","
                       << ProtocolToString(flow.protocol) << ","
                       << firstSeenStr << ","
                       << lastSeenStr << "\n";
            }

            csvFile.close();
            UpdateStatus(L"Export CSV réussi: " + std::wstring(fileName));
            MessageBoxW(g_hMainWindow, L"Export CSV réussi!", L"Succès", MB_OK | MB_ICONINFORMATION);
        } else {
            UpdateStatus(L"Erreur: Impossible de créer le fichier CSV");
            MessageBoxW(g_hMainWindow, L"Erreur lors de l'export!", L"Erreur", MB_OK | MB_ICONERROR);
        }
    }
}

// Initialiser la ListView
void InitListView(HWND hwnd) {
    g_hListView = GetDlgItem(hwnd, IDC_LISTVIEW);

    // Style
    DWORD style = LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER;
    ListView_SetExtendedListViewStyle(g_hListView, style);

    // Colonnes
    LVCOLUMNA lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    lvc.cx = 130;
    lvc.pszText = const_cast<char*>("SrcIP");
    ListView_InsertColumn(g_hListView, 0, &lvc);

    lvc.cx = 130;
    lvc.pszText = const_cast<char*>("DstIP");
    ListView_InsertColumn(g_hListView, 1, &lvc);

    lvc.cx = 100;
    lvc.pszText = const_cast<char*>("Packets");
    ListView_InsertColumn(g_hListView, 2, &lvc);

    lvc.cx = 120;
    lvc.pszText = const_cast<char*>("Bytes");
    ListView_InsertColumn(g_hListView, 3, &lvc);

    lvc.cx = 80;
    lvc.pszText = const_cast<char*>("Protocol");
    ListView_InsertColumn(g_hListView, 4, &lvc);

    lvc.cx = 100;
    lvc.pszText = const_cast<char*>("FirstSeen");
    ListView_InsertColumn(g_hListView, 5, &lvc);

    lvc.cx = 100;
    lvc.pszText = const_cast<char*>("LastSeen");
    ListView_InsertColumn(g_hListView, 6, &lvc);
}

// Procédure de fenêtre
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Champ port
            CreateWindowExW(0, L"STATIC", L"Port UDP:", WS_CHILD | WS_VISIBLE,
                           10, 10, 70, 20, hwnd, nullptr, nullptr, nullptr);
            g_hEditPort = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"2055",
                                         WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_NUMBER,
                                         90, 10, 80, 20, hwnd, (HMENU)IDC_EDIT_PORT, nullptr, nullptr);

            // Boutons
            CreateWindowExW(0, L"BUTTON", L"Démarrer",
                           WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                           190, 10, 100, 25, hwnd, (HMENU)IDC_BTN_START, nullptr, nullptr);

            CreateWindowExW(0, L"BUTTON", L"Arrêter",
                           WS_CHILD | WS_VISIBLE | WS_DISABLED,
                           310, 10, 100, 25, hwnd, (HMENU)IDC_BTN_STOP, nullptr, nullptr);

            CreateWindowExW(0, L"BUTTON", L"Exporter CSV",
                           WS_CHILD | WS_VISIBLE,
                           430, 10, 120, 25, hwnd, (HMENU)IDC_BTN_EXPORT, nullptr, nullptr);

            // ListView
            CreateWindowExW(0, WC_LISTVIEW, L"",
                           WS_CHILD | WS_VISIBLE | LVS_REPORT | WS_BORDER,
                           10, 50, 940, 480, hwnd, (HMENU)IDC_LISTVIEW, nullptr, nullptr);

            InitListView(hwnd);

            // Barre de statut
            g_hStatusBar = CreateWindowExW(0, STATUSCLASSNAME, nullptr,
                                          WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                          0, 0, 0, 0, hwnd, (HMENU)IDC_STATUSBAR, nullptr, nullptr);

            UpdateStatus(L"Prêt. Entrez le port UDP (défaut 2055 pour NetFlow) et cliquez Démarrer.");
            return 0;
        }

        case WM_SIZE: {
            if (g_hStatusBar) {
                SendMessageW(g_hStatusBar, WM_SIZE, 0, 0);
            }
            return 0;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_BTN_START: {
                    StartListener();
                    break;
                }
                case IDC_BTN_STOP: {
                    StopListener();
                    break;
                }
                case IDC_BTN_EXPORT: {
                    ExportToCSV();
                    break;
                }
            }
            return 0;
        }

        case WM_DESTROY:
            StopListener();
            DeleteCriticalSection(&g_flowsLock);
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// Point d'entrée
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Initialiser le log
    g_logPath = GetLogPath();
    LogMessage(L"=== NetFlowLiteCollector démarré ===");

    // Initialiser la section critique
    InitializeCriticalSection(&g_flowsLock);

    // Initialiser Common Controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    // Enregistrer la classe de fenêtre
    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"NetFlowLiteCollectorClass";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    RegisterClassExW(&wc);

    // Créer la fenêtre
    g_hMainWindow = CreateWindowExW(
        0,
        L"NetFlowLiteCollectorClass",
        L"NetFlowLiteCollector - Collecteur Léger NetFlow/sFlow - Ayi NEDJIMI Consultants",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 980, 600,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!g_hMainWindow) {
        LogMessage(L"Erreur: Impossible de créer la fenêtre principale");
        return 1;
    }

    ShowWindow(g_hMainWindow, nCmdShow);
    UpdateWindow(g_hMainWindow);

    // Boucle de messages
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    LogMessage(L"=== NetFlowLiteCollector terminé ===");
    return (int)msg.wParam;
}
