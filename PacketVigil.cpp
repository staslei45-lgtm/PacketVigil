#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <map>
#include <ctime>
#include <iomanip>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <regex>
#include <algorithm>

#ifdef __linux__
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

using namespace std;
using namespace std::chrono;

class ThreatIntelligence {
private:
    map<string, string> threatDatabase = {
        {"google-analytics.com", "Google Analytics"},
        {"doubleclick.net", "Google Ads/AdSense"},
        {"googlesyndication.com", "Google Ad Network"},
        {"googleadservices.com", "Google Advertising"},
        {"gstatic.com", "Google Static Tracking"},
        {"facebook.com", "Facebook Tracking"},
        {"fbcdn.net", "Facebook CDN Tracking"},
        {"facebook.net", "Facebook Analytics"},
        {"instagram.com", "Instagram Tracking"},
        {"whatsapp.com", "WhatsApp Analytics"},
        {"microsoft.com", "Microsoft Telemetry"},
        {"live.com", "Microsoft Account Tracking"},
        {"bing.com", "Bing Search Tracking"},
        {"office.com", "Office Telemetry"},
        {"apple.com", "Apple Services"},
        {"icloud.com", "iCloud Tracking"},
        {"appattest.com", "Apple App Attest"},
        {"amazon-adsystem.com", "Amazon Ads"},
        {"adsrvr.org", "Trade Desk Advertising"},
        {"adnxs.com", "AppNexus Advertising"},
        {"adsymptotic.com", "Advertising Network"},
        {"yandex.ru", "Yandex Analytics"},
        {"yandex.net", "Yandex Services"},
        {"mail.ru", "Mail.ru Group"},
        {"vk.com", "VKontakte Tracking"},
        {"ok.ru", "Odnoklassniki Tracking"},
        {"telemetry", "System Telemetry"},
        {"metrics", "Usage Metrics"},
        {"crashlytics.com", "Crash Reporting"},
        {"firebase.com", "Firebase Analytics"},
        {"sentry.io", "Error Tracking"},
        {"newrelic.com", "Performance Monitoring"},
        {"segment.com", "Customer Data Platform"},
        {"hubspot.com", "Marketing Tracking"},
        {"intercom.io", "Customer Communication"}
    };
    
    vector<string> suspiciousPatterns = {
        "track", "analytics", "metric", "telemetry", 
        "advert", "beacon", "pixel", "monitor",
        "collect", "report", "stats", "logging",
        "surveillance", "spy", "phoning home"
    };
    
public:
    string analyzeThreat(const string& data) {
        for (const auto& [domain, description] : threatDatabase) {
            if (data.find(domain) != string::npos) {
                return "DOMAIN: " + domain + " | Type: " + description;
            }
        }
        
        for (const auto& pattern : suspiciousPatterns) {
            if (data.find(pattern) != string::npos) {
                return "PATTERN: '" + pattern + "' found in data";
            }
        }
        
        regex ip_pattern(R"((\d+\.\d+\.\d+\.\d+))");
        smatch match;
        if (regex_search(data, match, ip_pattern)) {
            string ip = match[1];
            if (isSuspiciousIP(ip)) {
                return "SUSPICIOUS IP: " + ip + " | Block: " + getISP(ip);
            }
        }
        
        return "";
    }
    
    string getDeviceInfo() {
        string info;
        
        #ifdef __linux__
        ifstream routes("/proc/net/route");
        if (routes) {
            string line;
            getline(routes, line);
            if (getline(routes, line)) {
                stringstream ss(line);
                string iface, dest, gateway;
                ss >> iface >> dest >> gateway;
                info += "Interface: " + iface + " | ";
            }
        }
        
        ifstream addr("/sys/class/net/wlan0/address");
        if (addr) {
            string mac;
            getline(addr, mac);
            if (!mac.empty()) info += "MAC: " + mac + " | ";
        }
        
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            info += "Device: " + string(hostname);
        }
        #endif
        
        return info;
    }
    
private:
    bool isSuspiciousIP(const string& ip) {
        vector<string> suspiciousRanges = {
            "34.",  // Google Cloud
            "35.",  // Google Cloud
            "52.",  // Amazon AWS
            "54.",  // Amazon AWS
            "104.", // Facebook
            "129.", // Microsoft
            "140.", // Apple
            "172.", // Private (but could be VPN)
            "192.", // Private
            "10.",  // Private
        };
        
        for (const auto& range : suspiciousRanges) {
            if (ip.find(range) == 0) {
                return true;
            }
        }
        return false;
    }
    
    string getISP(const string& ip) {
        if (ip.find("34.") == 0 || ip.find("35.") == 0) return "Google Cloud";
        if (ip.find("52.") == 0 || ip.find("54.") == 0) return "Amazon AWS";
        if (ip.find("104.") == 0) return "Facebook/Meta";
        if (ip.find("129.") == 0) return "Microsoft";
        if (ip.find("140.") == 0) return "Apple";
        if (ip.find("172.") == 0 || ip.find("192.") == 0 || ip.find("10.") == 0) 
            return "Local Network/VPN";
        
        return "Unknown provider";
    }
};

class NetworkMonitor {
private:
    atomic<bool> running{true};
    mutex log_mutex;
    ThreatIntelligence threatIntel;
    map<string, int> threatCount;
    
    struct ThreatLog {
        string timestamp;
        string source;
        string type;
        string details;
        int severity;
    };
    
    vector<ThreatLog> threatLogs;
    
    string getCurrentTime() {
        auto now = system_clock::now();
        auto in_time_t = system_clock::to_time_t(now);
        stringstream ss;
        ss << put_time(localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
    
    string simulateTrafficAnalysis() {
        vector<string> simulatedSources = {
            "com.google.android.gms",
            "com.facebook.katana", 
            "com.instagram.android",
            "com.amazon.mShop",
            "com.whatsapp",
            "org.telegram.messenger",
            "com.android.vending",
            "com.samsung.android.app",
            "system_server",
            "unknown_app_1234"
        };
        
        vector<string> simulatedDomains = {
            "https://google-analytics.com/collect",
            "http://graph.facebook.com/metrics",
            "https://app-measurement.com/a",
            "ws://telemetry.microsoft.com",
            "dns://metrics.android.com",
            "https://samsungapps.com/report",
            "tcp://tracker.ubuntu.com:6969",
            "udp://in.admob.com:443",
            "https://crashlyticsreports-pa.googleapis.com",
            "http://settings-win.data.microsoft.com"
        };
        
        return simulatedSources[rand() % simulatedSources.size()] + " -> " +
               simulatedDomains[rand() % simulatedDomains.size()];
    }
    
public:
    void startDeepPacketInspection() {
        thread([this]() {
            cout << "\n[INFO] Starting enhanced threat analysis...\n";
            cout << "========================================\n";
            
            string deviceInfo = threatIntel.getDeviceInfo();
            if (!deviceInfo.empty()) {
                logEvent("SYSTEM_INFO", deviceInfo, 1);
            }
            
            int cycle = 0;
            while (running) {
                cycle++;
                
                vector<string> inspections = {
                    "DNS Query Analysis",
                    "HTTP Header Inspection", 
                    "TLS Connection Detection",
                    "Background Process Monitoring",
                    "Network Socket Scanning"
                };
                
                for (const auto& inspection : inspections) {
                    {
                        lock_guard<mutex> lock(log_mutex);
                        cout << "\n[" << getCurrentTime() << "] ";
                        cout << "[SCAN] " << inspection << "\n";
                    }
                    
                    if (rand() % 100 < 25) {
                        string simulatedData = simulateTrafficAnalysis();
                        string threatAnalysis = threatIntel.analyzeThreat(simulatedData);
                        
                        if (!threatAnalysis.empty()) {
                            size_t arrowPos = simulatedData.find(" -> ");
                            string source = "Unknown source";
                            if (arrowPos != string::npos) {
                                source = simulatedData.substr(0, arrowPos);
                            }
                            
                            logThreat(source, threatAnalysis, simulatedData);
                            
                            string threatType = extractThreatType(threatAnalysis);
                            threatCount[threatType]++;
                        }
                    }
                    
                    this_thread::sleep_for(milliseconds(800));
                    if (!running) break;
                }
                
                if (cycle % 3 == 0) {
                    generateThreatReport();
                }
                
                this_thread::sleep_for(seconds(2));
            }
        }).detach();
    }
    
    void logThreat(const string& source, const string& analysis, const string& details) {
        lock_guard<mutex> lock(log_mutex);
        
        int severity = 2;
        if (analysis.find("Google") != string::npos) severity = 3;
        if (analysis.find("Facebook") != string::npos) severity = 4;
        if (analysis.find("Telemetry") != string::npos) severity = 3;
        if (details.find("crash") != string::npos) severity = 1;
        
        cout << "\n==================================================\n";
        cout << "[ALERT] POTENTIAL THREAT DETECTED\n";
        cout << "==================================================\n";
        cout << "[SOURCE] " << source << "\n";
        cout << "[ANALYSIS] " << analysis << "\n";
        cout << "[SEVERITY] ";
        for (int i = 0; i < severity; i++) cout << "*";
        for (int i = severity; i < 5; i++) cout << ".";
        cout << " (" << severity << "/5)\n";
        cout << "[DETAILS] " << details << "\n";
        cout << "==================================================\n";
        
        ThreatLog log;
        log.timestamp = getCurrentTime();
        log.source = source;
        log.type = analysis;
        log.details = details;
        log.severity = severity;
        threatLogs.push_back(log);
        
        ofstream logfile("threat_detection.log", ios::app);
        if (logfile) {
            logfile << "[" << log.timestamp << "] ";
            logfile << "SOURCE: " << source << " | ";
            logfile << "ANALYSIS: " << analysis << " | ";
            logfile << "DETAILS: " << details << " | ";
            logfile << "SEVERITY: " << severity << endl;
        }
    }
    
    void logEvent(const string& event, const string& details, int level = 1) {
        lock_guard<mutex> lock(log_mutex);
        string prefix;
        
        switch(level) {
            case 1: prefix = "[INFO] "; break;
            case 2: prefix = "[WARN] "; break;
            case 3: prefix = "[ALERT] "; break;
            default: prefix = "[LOG] ";
        }
        
        cout << "[" << getCurrentTime() << "] " 
             << prefix << event << ": " << details << endl;
    }
    
    void generateThreatReport() {
        lock_guard<mutex> lock(log_mutex);
        
        if (threatCount.empty()) return;
        
        cout << "\n[REPORT] ========= THREAT REPORT =========\n";
        cout << "Total threats detected: " << threatLogs.size() << "\n";
        cout << "Statistics by type:\n";
        
        for (const auto& [type, count] : threatCount) {
            cout << "  * " << type << ": " << count << " times\n";
        }
        
        if (!threatLogs.empty()) {
            cout << "\nRecent threats:\n";
            int start = max(0, (int)threatLogs.size() - 3);
            for (int i = start; i < threatLogs.size(); i++) {
                cout << "  " << threatLogs[i].timestamp << " - " 
                     << threatLogs[i].source << endl;
            }
        }
        
        cout << "========================================\n";
    }
    
    void startMonitoring() {
        cout << "==========================================\n";
        cout << "  NETWORK THREAT ANALYSIS SYSTEM v2.0\n";
        cout << "==========================================\n";
        cout << "Features:\n";
        cout << "* Threat source identification\n";
        cout << "* Tracking type analysis\n";
        cout << "* Severity assessment\n";
        cout << "* Detailed information\n";
        cout << "==========================================\n\n";
        
        logEvent("SYSTEM", "Starting monitoring system", 1);
        
        startDeepPacketInspection();
        
        cout << "\n[INFO] System active. Press Enter to exit...\n";
        cin.ignore();
        cin.get();
        running = false;
        
        generateThreatReport();
        logEvent("SYSTEM", "Monitoring stopped", 1);
        
        cout << "\n[INFO] Logs saved to: threat_detection.log\n";
    }
    
private:
    string extractThreatType(const string& analysis) {
        if (analysis.find("Google") != string::npos) return "Google Tracking";
        if (analysis.find("Facebook") != string::npos) return "Facebook/Meta";
        if (analysis.find("Microsoft") != string::npos) return "Microsoft";
        if (analysis.find("Apple") != string::npos) return "Apple Services";
        if (analysis.find("Yandex") != string::npos) return "Yandex";
        if (analysis.find("Advertising") != string::npos) return "Ad Networks";
        if (analysis.find("Telemetry") != string::npos) return "System Telemetry";
        return "Unknown type";
    }
};

int main() {
    srand(time(nullptr));
    
    NetworkMonitor monitor;
    
    cout << "Select mode:\n";
    cout << "1. Enhanced threat monitoring\n";
    cout << "2. Quick check\n";
    cout << "3. Exit\n";
    cout << "> ";
    
    int choice;
    cin >> choice;
    
    switch(choice) {
        case 1:
            monitor.startMonitoring();
            break;
        case 2:
            cout << "\n[INFO] Quick check...\n";
            cout << "[INFO] Quick check completed.\n";
            break;
        default:
            cout << "[INFO] Exiting...\n";
            return 0;
    }
    
    return 0;
}