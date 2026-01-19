/*********************************************************************************
 * GHOST BEACON - A WiFi Probe Request Sniffer and Visualizer.
 * Hardware: ESP32 + WS2812 Ring (Data on GPIO 16)
 *********************************************************************************/

#include <WiFi.h>
#include <WebServer.h>
#include <FastLED.h>
#include <esp_wifi.h>
#include <Preferences.h>
#include <map>
#include <cstring> 

// --- HARDWARE DEFINITIONS ---
#define LED_PIN     16 
#define NUM_LEDS    24 
#define LED_TYPE    WS2812B
#define COLOR_ORDER GRB

// --- GLOBAL VARIABLES ---
CRGB leds[NUM_LEDS];
WebServer server(80);
Preferences prefs;

// Timers
unsigned long lastTriggerTime = 0;
unsigned long lastHopTime = 0;
unsigned long lastLedUpdate = 0;
unsigned long deauthWindowStart = 0;
unsigned long alarmStartTime = 0;

unsigned long ledTimeoutUnknown = 3000; 
unsigned long ledTimeoutKnown = 30000;   
unsigned long alarmDuration = 30000;     
CRGB alarmColor = CRGB::Red;

// --- CHANNEL HOPPING ---
int currentChannel = 1;
int hopStartChannel = 1;
int hopEndChannel = 13;
int hopSpeed = 200; 

// --- COLOR HASHING ---
std::map<String, CRGB> ssidColorMap;

const CRGB colorPalette[] = {
  CRGB::Red, CRGB::Green, CRGB::Blue, CRGB::White, CRGB::Black,
  CRGB::Yellow, CRGB::Orange, CRGB::Pink, CRGB::Purple, CRGB::Cyan,
  CRGB::Magenta, CRGB::Lime, CRGB::Teal, CRGB::Navy, CRGB::Gold,
  CRGB::Violet, CRGB::Olive, CRGB::Maroon, CRGB::Aqua, CRGB::Coral
};

// --- CONFIG STRUCTURES ---
struct Settings {
  char apSsid[32];
  char apPass[64];
  bool apHidden;
  char currentDate[11]; 
  char currentTime[6];  
  int deauthThreshold;
  bool deauthEnabled;
  bool logWildcards;
  int triggerMode; 
};

Settings settings;

// --- BLACKLIST MANAGEMENT ---
#define MAX_BLACKLIST 30
String blacklist[MAX_BLACKLIST];
int blacklistCount = 0;

bool isBlacklisted(String mac, String ssid) {
  for(int i=0; i<blacklistCount; i++) {
    String blItem = blacklist[i];
    if(blItem.length() >= 2 && blItem.substring(0,2) != "Wi") { 
       if(blItem.length() < 17) {
          if(mac.startsWith(blItem)) return true;
       } else {
          if(mac == blItem) return true;
       }
    }
    if(blItem == ssid) return true;
  }
  return false;
}

// --- DEVICE MANAGEMENT ---
#define MAX_DEVICES 50
struct Device {
  String mac;      
  String ssidName; 
  String name;     
  int effectId;
  int colorId;
  bool active;
};

Device knownDevices[MAX_DEVICES];
int knownDeviceCount = 0;

// --- EFFECTS & COLORS ---
const char* effectNames[] = {
  "Solid", "Rainbow", "Rainbow Glitter", "Confetti", "Sinelon", 
  "Juggle", "BPM", "Fire", "Color Wipe", "Theater Chase", 
  "Scanner", "Twinkle", "Breathing", "Cylon", "Noise",
  "Strobe", "Police", "Random Burst", "Running Lights", "Cycle"
};

// --- LOGGING ---
#define MAX_LOGS 200
struct LogEntry {
  unsigned long timestamp;
  String mac;
  String ssid;
  String rssi;
  bool isWildcard;
};
LogEntry logs[MAX_LOGS];
int logIndex = 0;
int totalLogs = 0;

// --- SNIFFER VARIABLES ---
bool snifferRunning = false;
unsigned long deauthCounter = 0;
bool alarmActive = false;

int currentEffect = 12; 
CRGB currentColor = CRGB::Green; // Default Ghost Color
unsigned long currentTimeout = ledTimeoutUnknown; 

// --- HELPER FUNCTIONS ---
String getMacString(const uint8_t *mac) {
  char macStr[18];
  snprintf(macStr, 18, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(macStr);
}

String getDateTimeStr() {
  return String(settings.currentDate) + " " + String(settings.currentTime);
}

CRGB getColorForSSID(String ssid) {
  if (ssidColorMap.count(ssid) > 0) {
    return ssidColorMap[ssid];
  }
  CRGB newColor;
  if (ssid == "<Wildcard>") {
    newColor = CRGB::Green; // Default Ghost Green
  } else {
    // Random "Ghostly" colors (Green, Teal, White with low red)
    uint8_t r = random8() % 50;
    uint8_t g = random8() % 255;
    uint8_t b = random8() % 50;
    newColor = CRGB(r, g, b);
  }
  ssidColorMap[ssid] = newColor;
  return newColor;
}

// --- PERSISTENCE (SAVE) ---
void saveConfig() {
  prefs.begin("GhostBeacon", false);
  
  prefs.putString("apSsid", settings.apSsid);
  prefs.putString("appass", settings.apPass); 
  prefs.putBool("aphidden", settings.apHidden);
  prefs.putString("date", settings.currentDate);
  prefs.putString("time", settings.currentTime);

  prefs.putInt("deauthThr", settings.deauthThreshold);
  prefs.putBool("deauthEn", settings.deauthEnabled);
  prefs.putBool("logWild", settings.logWildcards);
  prefs.putInt("trigMode", settings.triggerMode);

  prefs.putInt("hopStart", hopStartChannel);
  prefs.putInt("hopEnd", hopEndChannel);
  prefs.putInt("hopSpeed", hopSpeed);

  prefs.putInt("ledNew", ledTimeoutUnknown);
  prefs.putInt("ledKnown", ledTimeoutKnown);
  prefs.putInt("ledAlarm", alarmDuration);
  
  int alarmColorIdx = 0; 
  for(int i=0; i<20; i++) {
    if(colorPalette[i] == alarmColor) {
      alarmColorIdx = i;
      break;
    }
  }
  prefs.putInt("ledAlarmCol", alarmColorIdx);

  prefs.putInt("devCount", knownDeviceCount);
  
  char keyBuffer[32]; 
  for(int i=0; i<knownDeviceCount; i++) {
    snprintf(keyBuffer, 32, "dev_%d_mac", i);
    prefs.putString(keyBuffer, knownDevices[i].mac);
    snprintf(keyBuffer, 32, "dev_%d_ssid", i);
    prefs.putString(keyBuffer, knownDevices[i].ssidName);
    snprintf(keyBuffer, 32, "dev_%d_name", i);
    prefs.putString(keyBuffer, knownDevices[i].name);
    snprintf(keyBuffer, 32, "dev_%d_eff", i);
    prefs.putInt(keyBuffer, knownDevices[i].effectId);
    snprintf(keyBuffer, 32, "dev_%d_col", i);
    prefs.putInt(keyBuffer, knownDevices[i].colorId);
    snprintf(keyBuffer, 32, "dev_%d_act", i);
    prefs.putBool(keyBuffer, knownDevices[i].active);
  }

  prefs.putInt("blCount", blacklistCount);
  for(int i=0; i<blacklistCount; i++) {
     snprintf(keyBuffer, 32, "bl_%d", i);
     prefs.putString(keyBuffer, blacklist[i]);
  }
  
  prefs.end();
  Serial.println("Configuration saved.");
}

void loadConfig() {
  prefs.begin("GhostBeacon", true); 
  
  // DEFAULTS
  strcpy(settings.apSsid, "GHOST_BEACON");
  strcpy(settings.apPass, "GhostGetConf34");
  settings.apHidden = false;
  strcpy(settings.currentDate, "2024-01-01");
  strcpy(settings.currentTime, "12:00");
  settings.deauthThreshold = 5;
  settings.deauthEnabled = true;
  settings.logWildcards = true;
  settings.triggerMode = 0; 

  if(prefs.isKey("apSsid")) {
    String s = prefs.getString("apSsid", "GHOST_BEACON");
    strncpy(settings.apSsid, s.c_str(), 31); settings.apSsid[31] = 0;
  }
  if(prefs.isKey("appass")) {
    String s = prefs.getString("appass", "GhostGetConf34");
    strncpy(settings.apPass, s.c_str(), 63); settings.apPass[63] = 0;
  }
  settings.apHidden = prefs.getBool("aphidden", false);
  if(prefs.isKey("date")) {
    String s = prefs.getString("date", "2024-01-01");
    strncpy(settings.currentDate, s.c_str(), 10); settings.currentDate[10] = 0;
  }
  
  if(prefs.isKey("time")) {
    String tempTime = prefs.getString("time", "12:00");
    strncpy(settings.currentTime, tempTime.c_str(), 5);
    settings.currentTime[5] = '\0';
  }
  
  settings.deauthThreshold = prefs.getInt("deauthThr", 5);
  settings.deauthEnabled = prefs.getBool("deauthEn", true);
  settings.logWildcards = prefs.getBool("logWild", true);
  settings.triggerMode = prefs.getInt("trigMode", 0);

  hopStartChannel = prefs.getInt("hopStart", 1);
  hopEndChannel = prefs.getInt("hopEnd", 13);
  hopSpeed = prefs.getInt("hopSpeed", 200);

  ledTimeoutUnknown = prefs.getInt("ledNew", 3000);
  ledTimeoutKnown = prefs.getInt("ledKnown", 30000);
  alarmDuration = prefs.getInt("ledAlarm", 30000);
  
  int alarmColIdx = prefs.getInt("ledAlarmCol", 0);
  if(alarmColIdx >= 0 && alarmColIdx < 20) {
    alarmColor = colorPalette[alarmColIdx];
  } else {
    alarmColor = CRGB::Red;
  }

  int savedCount = prefs.getInt("devCount", 0);
  if(savedCount > MAX_DEVICES) savedCount = MAX_DEVICES;
  knownDeviceCount = 0;
  
  char keyBuffer[32];
  for(int i=0; i<savedCount; i++) {
    snprintf(keyBuffer, 32, "dev_%d_mac", i);
    if(prefs.isKey(keyBuffer)) {
      knownDevices[knownDeviceCount].mac = prefs.getString(keyBuffer, "");
      snprintf(keyBuffer, 32, "dev_%d_ssid", i);
      knownDevices[knownDeviceCount].ssidName = prefs.getString(keyBuffer, "");
      snprintf(keyBuffer, 32, "dev_%d_name", i);
      knownDevices[knownDeviceCount].name = prefs.getString(keyBuffer, "Unnamed");
      snprintf(keyBuffer, 32, "dev_%d_eff", i);
      knownDevices[knownDeviceCount].effectId = prefs.getInt(keyBuffer, 0);
      snprintf(keyBuffer, 32, "dev_%d_col", i);
      knownDevices[knownDeviceCount].colorId = prefs.getInt(keyBuffer, 0);
      snprintf(keyBuffer, 32, "dev_%d_act", i);
      knownDevices[knownDeviceCount].active = prefs.getBool(keyBuffer, true);
      knownDeviceCount++;
    }
  }

  int blSaved = prefs.getInt("blCount", 0);
  if(blSaved > MAX_BLACKLIST) blSaved = MAX_BLACKLIST;
  blacklistCount = 0;
  for(int i=0; i<blSaved; i++) {
     snprintf(keyBuffer, 32, "bl_%d", i);
     if(prefs.isKey(keyBuffer)) {
        blacklist[blacklistCount] = prefs.getString(keyBuffer, "");
        blacklistCount++;
     }
  }

  prefs.end();
  Serial.println("Configuration loaded.");
}

// --- DEVICE LOGIC ---
int findDeviceIndex(String mac, String ssid) {
  for(int i=0; i<knownDeviceCount; i++) {
    if(knownDevices[i].mac.length() > 0 && knownDevices[i].mac.length() < 17) {
       if(mac.startsWith(knownDevices[i].mac)) return i;
    }
    else if(knownDevices[i].mac == mac) {
      return i;
    }
    else if(knownDevices[i].ssidName.length() > 0 && knownDevices[i].ssidName == ssid) {
      return i;
    }
  }
  return -1;
}

// --- LED EFFECTS ---
CRGB myHeatColor(uint8_t temperature) {
  CRGB heatcolor;
  heatcolor.r = temperature;
  heatcolor.g = temperature > 127 ? (temperature - 128) * 2 : 0;
  heatcolor.b = 0;
  return heatcolor;
}

void runEffect(int effectId, CRGB color) {
  if(alarmActive) {
    if(millis() % 200 < 100) fill_solid(leds, NUM_LEDS, alarmColor);
    else fill_solid(leds, NUM_LEDS, CRGB::Black);
    FastLED.show();
    return;
  }

  uint8_t gHue = millis() / 1000; 

  switch(effectId) {
    case 0: fill_solid(leds, NUM_LEDS, color); break;
    case 1: fill_rainbow(leds, NUM_LEDS, gHue, 7); break;
    case 2: fill_rainbow(leds, NUM_LEDS, gHue, 7); if(random8() < 80) leds[random16(NUM_LEDS)] += CRGB::White; break;
    case 3: {
        fadeToBlackBy(leds, NUM_LEDS, 10);
        int pos = random16(NUM_LEDS);
        leds[pos] += color;
        break;
      }
    case 4: {
        fadeToBlackBy(leds, NUM_LEDS, 20);
        int ledPos = beatsin16(13, 0, NUM_LEDS-1);
        leds[ledPos] += color;
        break;
      }
    case 5: {
        fadeToBlackBy(leds, NUM_LEDS, 20);
        for( int i = 0; i < 8; i++) {
          leds[beatsin16(i+7, 0, NUM_LEDS-1)] |= color;
        }
        break;
      }
    case 6: {
        uint8_t beat = beatsin8( 62, 64, 255);
        for( int i = 0; i < NUM_LEDS; i++) {
          leds[i] = ColorFromPalette(RainbowColors_p, gHue+(i*2), beat-gHue+(i*10));
        }
        break;
      }
    case 7: {
        fadeToBlackBy(leds, NUM_LEDS, 10);
        for(int i=0; i<NUM_LEDS; i++) {
          leds[i] = myHeatColor((millis()/20 + i)%255).nscale8_video(150);
        }
        break;
      }
    case 8: 
        fill_solid(leds, NUM_LEDS, color); 
        if(millis() % 1000 < 500) fill_solid(leds, NUM_LEDS/2, CRGB::Black); 
        break;
    case 9: {
        static int tc_pos = 0;
        if(millis() % 100 < 10) tc_pos = (tc_pos + 1) % 3;
        for(int i=0; i<NUM_LEDS; i++) {
           if((i + tc_pos) % 3 == 0) leds[i] = color;
           else leds[i] = CRGB::Black;
        }
        break;
      }
    case 10: {
        static int scan_pos = 0;
        static bool scan_dir = true;
        if(millis() % 50 < 5) {
          if(scan_dir) scan_pos++; else scan_pos--;
          if(scan_pos >= NUM_LEDS || scan_pos <= 0) scan_dir = !scan_dir;
        }
        fill_solid(leds, NUM_LEDS, CRGB::Black);
        leds[scan_pos] = color;
        if(scan_pos > 0) leds[scan_pos-1] = color.nscale8_video(100);
        if(scan_pos < NUM_LEDS-1) leds[scan_pos+1] = color.nscale8_video(100);
        break;
      }
    case 11: {
        fadeToBlackBy(leds, NUM_LEDS, 5);
        if(random8() < 50) leds[random16(NUM_LEDS)] = color;
        break;
      }
    case 12: {
        static uint8_t breathe = 0;
        static bool breathUp = true;
        if(millis() % 20 < 5) {
          if(breathUp) breathe++; else breathe--;
          if(breathe >= 255) breathUp = false;
          if(breathe <= 0) breathUp = true;
        }
        fill_solid(leds, NUM_LEDS, color.nscale8_video(breathe));
        break;
      }
    default: fill_solid(leds, NUM_LEDS, CRGB::Purple); break;
  }
  FastLED.show();
}

// --- WIFI SNIFFER ---
void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const uint8_t *payload = ppkt->payload;
  int len = ppkt->rx_ctrl.sig_len;

  uint8_t frame_type = payload[0] & 0xFC; 

  // Probe Request (Subtype 4) -> 0x40
  if (frame_type == 0x40) { 
    int pos = 24; 

    uint8_t mac[6];
    memcpy(mac, payload + 10, 6); 
    String macStr = getMacString(mac);

    String detectedSSID = "";
    while (pos < len) {
      uint8_t tag = payload[pos];
      uint8_t taglen = payload[pos + 1];
      if (pos + 2 + taglen > len) break; 
      if (tag == 0 && taglen > 0) { 
        char ssid[taglen + 1];
        memcpy(ssid, payload + pos + 2, taglen);
        ssid[taglen] = '\0';
        detectedSSID = String(ssid);
        break;
      }
      pos += 2 + taglen;
    }

    bool isWildcard = detectedSSID.isEmpty();
    String logSSID = isWildcard ? "<Wildcard>" : detectedSSID;

    // BLACKLIST CHECK
    if(isBlacklisted(macStr, logSSID)) {
        return; 
    }

    int devIdx = findDeviceIndex(macStr, detectedSSID);
    
    bool trigger = false;
    if(settings.triggerMode == 0) { 
       if(devIdx == -1) trigger = true;
    } else if (settings.triggerMode == 1) { 
       trigger = true;
    } else if (settings.triggerMode == 2) { 
       if(devIdx != -1) trigger = true;
    }

    if(trigger) {
      if(devIdx != -1 && knownDevices[devIdx].active) {
        currentEffect = knownDevices[devIdx].effectId;
        currentColor = colorPalette[knownDevices[devIdx].colorId];
        currentTimeout = ledTimeoutKnown; 
      } else {
        currentEffect = 12; 
        currentColor = getColorForSSID(logSSID);
        currentTimeout = ledTimeoutUnknown; 
      }
      lastTriggerTime = millis();
    }

    if((!isWildcard || settings.logWildcards) && !alarmActive) {
      logs[logIndex].timestamp = millis();
      logs[logIndex].mac = macStr;
      logs[logIndex].ssid = logSSID;
      logs[logIndex].rssi = String(ppkt->rx_ctrl.rssi);
      logs[logIndex].isWildcard = isWildcard;
      
      logIndex = (logIndex + 1) % MAX_LOGS;
      totalLogs++;
      if(totalLogs > MAX_LOGS) totalLogs = MAX_LOGS; 
    }
  }
  // Deauth Check (Subtype 12) -> 0xC0
  else if (frame_type == 0xC0 && settings.deauthEnabled) {
    unsigned long now = millis();
    if(now - deauthWindowStart > 1000) { 
        deauthWindowStart = now;
        deauthCounter = 1;
    } else {
        deauthCounter++;
        if(deauthCounter >= settings.deauthThreshold) {
            if(!alarmActive) {
                alarmActive = true;
                alarmStartTime = millis();
            }
        }
    }
  }
}

// --- WEB SERVER HTML ---
String getHTML() {
  String css = R"rawliteral(
<style>
  body { font-family: 'Courier New', monospace; background-color: #0d1117; color: #00ff00; margin: 0; padding: 20px; }
  h1 { text-shadow: 2px 2px #ff0000; color: #ffffff; border-bottom: 2px solid #00ff00; text-transform: uppercase; letter-spacing: 5px; }
  .card { border: 1px solid #00ff00; padding: 15px; margin-bottom: 20px; background: #161b22; box-shadow: 0 0 10px rgba(0, 255, 0, 0.2); }
  input, select, button { background: #000; color: #00ff00; border: 1px solid #00ff00; padding: 8px; margin: 5px; font-family: inherit; }
  button:hover { background: #00ff00; color: #000; cursor: pointer; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }
  th, td { border: 1px solid #333; padding: 5px; text-align: left; }
  th { color: #00ffff; }
  .log-entry { font-size: 10px; border-bottom: 1px solid #333; padding: 2px; }
  .section-title { color: #00ffff; font-weight: bold; margin-top: 20px; text-shadow: 0 0 5px #00ffff; }
</style>
  )rawliteral";

  String html = "<!DOCTYPE html><html><head><title>GHOST BEACON</title><meta name='viewport' content='width=device-width, initial-scale=1'>";
  html += css;
  html += "<script>";
  html += "function updateLog() { fetch('/log').then(r=>r.json()).then(d=>{ document.getElementById('logbox').innerHTML = d.map(l=>`<div class='log-entry'>[${l.ts}] ${l.mac} | ${l.ssid} | ${l.rssi}dB</div>`).join(''); }); }";
  html += "setInterval(updateLog, 1000);";
  html += "</script></head><body>";

  html += "<h1>GHOST BEACON CONFIG</h1>";

  // SYSTEM & NETWORK
  html += "<div class='card'>";
  html += "<div class='section-title'>SYSTEM & NETWORK</div>";
  html += "<form action='/save' method='POST'>";
  html += "AP SSID: <input name='apssid' value='" + String(settings.apSsid) + "'><br>";
  html += "AP Pass: <input name='appass' value='" + String(settings.apPass) + "'><br>";
  html += "Hidden AP: <select name='aphidden'><option value='0'" + String(settings.apHidden?"":" selected") + ">Off</option><option value='1'" + String(settings.apHidden?" selected":"") + ">On</option></select><br>";
  html += "Date: <input name='date' value='" + String(settings.currentDate) + "'><br>";
  html += "Time: <input name='time' value='" + String(settings.currentTime) + "'><br>";
  html += "<button type='submit'>SAVE & REBOOT</button>";
  html += "</form></div>";

  // LED SETTINGS
  html += "<div class='card'>";
  html += "<div class='section-title'>LED SETTINGS</div>";
  html += "<form action='/save' method='POST'>";
  html += "New Dev Duration (ms): <input type='number' name='ledNew' value='" + String(ledTimeoutUnknown) + "'><br>";
  html += "Known Dev Duration (ms): <input type='number' name='ledKnown' value='" + String(ledTimeoutKnown) + "'><br>";
  html += "Alarm Duration (ms): <input type='number' name='ledAlarm' value='" + String(alarmDuration) + "'><br>";
  html += "Alarm Color: <select name='ledAlarmCol'>";
  const char* cNames[] = {"Red","Green","Blue","White","Black","Yellow","Orange","Pink","Purple","Cyan","Magenta","Lime","Teal","Navy","Gold","Violet","Olive","Maroon","Aqua","Coral"};
  int alarmColorIdx = -1;
  for(int i=0; i<20; i++) {
    if(colorPalette[i] == alarmColor) alarmColorIdx = i;
    html += "<option value='"+String(i)+"' "+String(alarmColorIdx==i?"selected":"")+">"+String(cNames[i])+"</option>";
  }
  html += "</select><br>";
  html += "<button type='submit'>SAVE</button></form></div>";

  // CHANNEL HOPPING
  html += "<div class='card'>";
  html += "<div class='section-title'>CHANNEL HOPPING</div>";
  html += "<form action='/save' method='POST'>";
  html += "Start Channel: <input type='number' name='hopStart' value='" + String(hopStartChannel) + "' min='1' max='13'><br>";
  html += "End Channel: <input type='number' name='hopEnd' value='" + String(hopEndChannel) + "' min='1' max='13'><br>";
  html += "Speed (ms): <input type='number' name='hopSpeed' value='" + String(hopSpeed) + "' min='50'><br>";
  html += "<button type='submit'>SAVE</button></form></div>";

  // DETECTOR SETTINGS
  html += "<div class='card'>";
  html += "<div class='section-title'>DETECTOR SETTINGS</div>";
  html += "<form action='/save' method='POST'>";
  html += "Trigger Mode: <select name='trigmode'>";
  html += "<option value='0'" + String(settings.triggerMode==0?" selected":"") + ">Only New Devices</option>";
  html += "<option value='1'" + String(settings.triggerMode==1?" selected":"") + ">All Devices</option>";
  html += "<option value='2'" + String(settings.triggerMode==2?" selected":"") + ">Only Known Devices</option>";
  html += "</select><br>";
  html += "Log Wildcards: <select name='logwild'><option value='1'" + String(settings.logWildcards?" selected":"") + ">Yes</option><option value='0'" + String(!settings.logWildcards?" selected":"") + ">No</option></select><br>";
  html += "Deauth Detector: <select name='deauthen'><option value='1'" + String(settings.deauthEnabled?" selected":"") + ">On</option><option value='0'" + String(!settings.deauthEnabled?" selected":"") + ">Off</option></select><br>";
  html += "Deauth Threshold: <input type='number' name='deauththr' value='" + String(settings.deauthThreshold) + "'><br>";
  html += "<button type='submit'>SAVE</button></form></div>";

  // BLACKLIST
  html += "<div class='card'>";
  html += "<div class='section-title'>BLACKLIST (EXCLUDE)</div>";
  html += "<form action='/addbl' method='POST'>";
  html += "MAC/SSID to Ignore: <input name='blitem'>";
  html += "<button type='submit'>ADD</button>";
  html += "</form><br>";
  html += "<table><tr><th>Item</th><th>Del</th></tr>";
  for(int i=0; i<blacklistCount; i++) {
    html += "<tr><form action='/delbl' method='POST'>";
    html += "<input type='hidden' name='idx' value='"+String(i)+"'>";
    html += "<td><small>"+blacklist[i]+"</small></td>";
    html += "<td><button type='submit'>X</button></td>";
    html += "</form></tr>";
  }
  html += "</table></div>";

  // KNOWN DEVICES
  html += "<div class='card'>";
  html += "<div class='section-title'>KNOWN DEVICES</div>";
  html += "<form action='/add' method='POST'>";
  html += "Name: <input name='name'> ";
  html += "MAC/Prefix: <input name='mac'> ";
  html += "SSID: <input name='ssid'><br>";
  html += "Effect: <select name='eff'>";
  for(int i=0; i<20; i++) html += "<option value='"+String(i)+"'>"+String(effectNames[i])+"</option>";
  html += "</select> ";
  html += "Color: <select name='col'>";
  for(int i=0; i<20; i++) html += "<option value='"+String(i)+"'>"+String(cNames[i])+"</option>";
  html += "</select>";
  html += "<button type='submit'>ADD DEVICE</button>";
  html += "</form>";
  
  html += "<table><tr><th>Name</th><th>MAC/SSID</th><th>Eff</th><th>Act</th><th>Del</th></tr>";
  for(int i=0; i<knownDeviceCount; i++) {
    html += "<tr><form action='/edit' method='POST'>";
    html += "<input type='hidden' name='idx' value='"+String(i)+"'>";
    html += "<td><input name='name' value='"+knownDevices[i].name+"'></td>";
    html += "<td><small>"+knownDevices[i].mac;
    if(knownDevices[i].ssidName.length()>0) html += " / "+knownDevices[i].ssidName;
    html += "</small></td>";
    html += "<td><select name='eff'>";
    for(int e=0; e<20; e++) html += "<option value='"+String(e)+"' "+String(knownDevices[i].effectId==e?"selected":"")+">"+effectNames[e]+"</option>";
    html += "</select></td>";
    html += "<td><input type='checkbox' name='act' "+String(knownDevices[i].active?"checked":"")+"></td>";
    html += "<td><button type='submit' name='del' value='1'>X</button></td>";
    html += "</form></tr>";
  }
  html += "</table></div>";

  html += "<div class='card'>";
  html += "<div class='section-title'>LIVE LOG</div>";
  html += "<a href='/csv' style='color:#00ffff'>Download CSV</a><br>";
  html += "<div id='logbox' style='height: 200px; overflow-y: scroll; background: #000; border: 1px solid #333; padding: 5px;'></div>";
  html += "</div>";

  html += "</body></html>";
  return html;
}

void handleRoot() {
  server.send(200, "text/html", getHTML());
}

void handleSave() {
  if(server.hasArg("apssid")) {
    String s = server.arg("apssid");
    strncpy(settings.apSsid, s.c_str(), 31); settings.apSsid[31] = 0;
  }
  if(server.hasArg("appass")) {
    String s = server.arg("appass");
    strncpy(settings.apPass, s.c_str(), 63); settings.apPass[63] = 0;
  }
  settings.apHidden = (server.arg("aphidden") == "1");
  if(server.hasArg("date")) {
    String s = server.arg("date");
    strncpy(settings.currentDate, s.c_str(), 10); settings.currentDate[10] = 0;
  }
  if(server.hasArg("time")) {
    String s = server.arg("time");
    strncpy(settings.currentTime, s.c_str(), 5); settings.currentTime[5] = 0;
  }
  
  if(server.hasArg("trigmode")) settings.triggerMode = server.arg("trigmode").toInt();
  settings.logWildcards = (server.arg("logwild") == "1");
  settings.deauthEnabled = (server.arg("deauthen") == "1");
  if(server.hasArg("deauththr")) settings.deauthThreshold = server.arg("deauththr").toInt();

  if(server.hasArg("hopStart")) hopStartChannel = server.arg("hopStart").toInt();
  if(server.hasArg("hopEnd")) hopEndChannel = server.arg("hopEnd").toInt();
  if(server.hasArg("hopSpeed")) hopSpeed = server.arg("hopSpeed").toInt();

  if(server.hasArg("ledNew")) ledTimeoutUnknown = server.arg("ledNew").toInt();
  if(server.hasArg("ledKnown")) ledTimeoutKnown = server.arg("ledKnown").toInt();
  if(server.hasArg("ledAlarm")) alarmDuration = server.arg("ledAlarm").toInt();
  if(server.hasArg("ledAlarmCol")) alarmColor = colorPalette[server.arg("ledAlarmCol").toInt()];

  saveConfig();
  String msg = "<body style='background:#000;color:#0f0;'>SAVED! Rebooting... <meta http-equiv='refresh' content='2;url=/'></body>";
  server.send(200, "text/html", msg);
  delay(1000);
  ESP.restart();
}

void handleAdd() {
  if(knownDeviceCount < MAX_DEVICES) {
    knownDevices[knownDeviceCount].name = server.arg("name");
    knownDevices[knownDeviceCount].mac = server.arg("mac");
    knownDevices[knownDeviceCount].ssidName = server.arg("ssid");
    knownDevices[knownDeviceCount].effectId = server.arg("eff").toInt();
    knownDevices[knownDeviceCount].colorId = server.arg("col").toInt();
    knownDevices[knownDeviceCount].active = true;
    knownDeviceCount++;
    saveConfig();
  }
  handleRoot();
}

void handleAddBL() {
  if(blacklistCount < MAX_BLACKLIST) {
    String item = server.arg("blitem");
    item.trim();
    if(item.length() > 0) {
        blacklist[blacklistCount] = item;
        blacklistCount++;
        saveConfig();
    }
  }
  handleRoot();
}

void handleDelBL() {
  int idx = server.arg("idx").toInt();
  if(idx >= 0 && idx < blacklistCount) {
    for(int i=idx; i<blacklistCount-1; i++) blacklist[i] = blacklist[i+1];
    blacklistCount--;
    saveConfig();
  }
  handleRoot();
}

void handleEdit() {
  int idx = server.arg("idx").toInt();
  if(idx >= 0 && idx < knownDeviceCount) {
    if(server.hasArg("del") && server.arg("del") == "1") {
      for(int i=idx; i<knownDeviceCount-1; i++) knownDevices[i] = knownDevices[i+1];
      knownDeviceCount--;
    } else {
      knownDevices[idx].name = server.arg("name");
      knownDevices[idx].effectId = server.arg("eff").toInt();
      knownDevices[idx].active = server.hasArg("act");
    }
    saveConfig();
  }
  handleRoot();
}

void handleLogJSON() {
  String json = "[";
  bool firstEntry = true;
  int current = (logIndex - 1 + MAX_LOGS) % MAX_LOGS;
  for(int i=0; i<20; i++) {
      if(logs[current].timestamp != 0) {
          if(!firstEntry) json += ",";
          firstEntry = false;
          json += "{";
          json += "\"ts\":\"" + String((unsigned long)(logs[current].timestamp / 1000)) + "\","; 
          json += "\"mac\":\"" + logs[current].mac + "\",";
          json += "\"ssid\":\"" + logs[current].ssid + "\",";
          json += "\"rssi\":\"" + logs[current].rssi + "\"";
          json += "}";
      }
      current = (current - 1 + MAX_LOGS) % MAX_LOGS;
  }
  json += "]";
  server.send(200, "application/json", json);
}

void handleCSV() {
  String csv = "Timestamp,MAC,SSID,RSSI\n";
  for(int i=0; i<MAX_LOGS; i++) {
    if(logs[i].timestamp != 0) {
       csv += String((unsigned long)(logs[i].timestamp / 1000)) + "," + logs[i].mac + "," + logs[i].ssid + "," + logs[i].rssi + "\n";
    }
  }
  server.sendHeader("Content-Disposition", "attachment; filename=ghost_log.csv");
  server.send(200, "text/csv", csv);
}

bool isIp(String str) {
  for (size_t i = 0; i < str.length(); i++) {
    int c = str.charAt(i);
    if (c != '.' && (c < '0' || c > '9')) {
      return false;
    }
  }
  return true;
}

String toStringIp(IPAddress ip) {
  String res = "";
  for (int i = 0; i < 3; i++) {
    res += String((ip >> (8 * i)) & 0xFF) + ".";
  }
  res += String(((ip >> 8 * 3)) & 0xFF);
  return res;
}

// --- SETUP & LOOP ---
void setup() {
  Serial.begin(115200);
  
  FastLED.addLeds<LED_TYPE, LED_PIN, COLOR_ORDER>(leds, NUM_LEDS);
  FastLED.setBrightness(50);
  fill_solid(leds, NUM_LEDS, CRGB::Black); 
  FastLED.show();

  loadConfig();

  WiFi.mode(WIFI_AP);
  
  // Force WPA2 (Last Param 2) to fix connection issues
  WiFi.softAP(settings.apSsid, settings.apPass, 1, settings.apHidden, 2);
  
  delay(100);
  
  // DEBUG OUTPUT
  Serial.println("------------------------------------------------");
  Serial.println("GHOST BEACON STARTED");
  Serial.print("SSID: ");
  Serial.println(settings.apSsid);
  Serial.print("PASSWORD: ");
  Serial.println(settings.apPass);
  Serial.print("IP: ");
  Serial.println(WiFi.softAPIP());
  Serial.println("------------------------------------------------");

  server.on("/", handleRoot);
  server.on("/save", handleSave);
  server.on("/add", handleAdd);
  server.on("/addbl", handleAddBL);
  server.on("/delbl", handleDelBL);
  server.on("/edit", handleEdit);
  server.on("/log", handleLogJSON);
  server.on("/csv", handleCSV);
  
  server.onNotFound([]() {
    if(!isIp(server.hostHeader())) {
        server.sendHeader("Location", String("http://") + toStringIp(server.client().localIP()), true);
        server.send(302, "text/plain", ""); 
    } else {
        server.send(404, "text/plain", "Not Found");
    }
  });

  server.begin();

  esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
  esp_wifi_set_promiscuous(true);

  fill_solid(leds, NUM_LEDS, CRGB::Black);
  FastLED.show();
}

void loop() {
  server.handleClient();
  
  // CHANNEL HOPPING LOGIC
  if(millis() - lastHopTime > hopSpeed) {
    lastHopTime = millis();
    currentChannel++;
    if(currentChannel > hopEndChannel) {
      currentChannel = hopStartChannel;
    }
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  }

  // 1. Handle Alarm
  if(alarmActive) {
    if(millis() - alarmStartTime > alarmDuration) {
        alarmActive = false;
        deauthCounter = 0;
    }
  }

  // 2. Handle LEDs Logic
  if (alarmActive) {
    runEffect(10, alarmColor); 
  } 
  else {
    if (millis() - lastTriggerTime < currentTimeout) {
      runEffect(currentEffect, currentColor);
    } 
    else {
      fill_solid(leds, NUM_LEDS, CRGB::Black);
      FastLED.show();
    }
  }
  
  delay(20);
}
