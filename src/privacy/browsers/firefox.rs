// src/privacy/browsers/firefox.rs
use serde::{Serialize, Deserialize};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use crate::firefox::profile::FirefoxProfiler;
use super::super::PrivacyError;
use super::super::levels::ProtectionLevel;
use utoipa::ToSchema;

// Firefox privacy settings
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct FirefoxSettings {
    pub disable_telemetry: bool,
    pub enable_tracking_protection: bool,
    pub enable_do_not_track: bool,
    pub disable_geolocation: bool,
    pub disable_webrtc: bool,
    pub disable_prefetch: bool,
    pub disable_pocket: bool,
    pub enforce_https: bool,
    pub disable_cookies: bool,
    pub disable_canvas: bool,
    pub disable_webgl: bool,
    pub disable_audio_api: bool,
    pub standardize_fonts: bool,
    pub spoof_timezone: bool,
    pub spoof_language: bool,
    pub spoof_screen_size: bool,
    pub spoof_user_agent: bool,
}

pub struct FirefoxHardener {
    profiles: Vec<(String, PathBuf)>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FirefoxStatus {
    pub is_installed: bool,
    pub is_hardened: bool,
    pub tracking_protection: bool,
    pub do_not_track: bool,
    pub resist_fingerprinting: bool,
    pub canvas_protection: bool,
    pub webgl_disabled: bool,
    pub geolocation_disabled: bool,
    pub webrtc_disabled: bool,
    pub cookie_restrictions: bool,
    pub https_only: bool,
}

impl FirefoxHardener {
    pub fn new() -> Result<Self, PrivacyError> {
        // Find Firefox profiles
        let profiler = FirefoxProfiler::new();
        let profiles = profiler.find_profiles();
        
        if profiles.is_empty() {
            return Err(PrivacyError::FirefoxNotFound);
        }
        
        Ok(Self { profiles })
    }
    
    // Apply hardening based on protection level
    pub fn apply_hardening(&self, level: ProtectionLevel, settings: &FirefoxSettings) -> Result<Vec<String>, PrivacyError> {
        let mut applied_settings = Vec::new();
        
        // Apply to all profiles
        for (profile_name, profile_path) in &self.profiles {
            let user_js_path = profile_path.join("user.js");
            
            // Generate the user.js content
            let mut content = String::new();
            content.push_str("// RustVault Privacy Protection - Firefox Hardening\n");
            content.push_str("// Protection Level: ");
            content.push_str(&level.to_string());
            content.push_str("\n\n");
            
            // Add privacy settings based on the configuration
            if settings.disable_telemetry {
                content.push_str("// Disable telemetry\n");
                content.push_str("user_pref(\"toolkit.telemetry.enabled\", false);\n");
                content.push_str("user_pref(\"toolkit.telemetry.unified\", false);\n");
                content.push_str("user_pref(\"toolkit.telemetry.archive.enabled\", false);\n");
                content.push_str("user_pref(\"browser.ping-centre.telemetry\", false);\n");
                content.push_str("user_pref(\"browser.newtabpage.activity-stream.feeds.telemetry\", false);\n");
                content.push_str("user_pref(\"browser.newtabpage.activity-stream.telemetry\", false);\n");
                applied_settings.push("Disable telemetry".to_string());
            }
            
            if settings.enable_tracking_protection {
                content.push_str("\n// Enable tracking protection\n");
                content.push_str("user_pref(\"privacy.trackingprotection.enabled\", true);\n");
                content.push_str("user_pref(\"privacy.trackingprotection.pbmode.enabled\", true);\n");
                content.push_str("user_pref(\"privacy.trackingprotection.fingerprinting.enabled\", true);\n");
                content.push_str("user_pref(\"privacy.trackingprotection.cryptomining.enabled\", true);\n");
                applied_settings.push("Enable tracking protection".to_string());
            }
            
            if settings.enable_do_not_track {
                content.push_str("\n// Enable Do Not Track\n");
                content.push_str("user_pref(\"privacy.donottrackheader.enabled\", true);\n");
                applied_settings.push("Enable Do Not Track".to_string());
            }
            
            if settings.disable_geolocation {
                content.push_str("\n// Disable geolocation\n");
                content.push_str("user_pref(\"geo.enabled\", false);\n");
                content.push_str("user_pref(\"geo.wifi.uri\", \"\");\n");
                applied_settings.push("Disable geolocation".to_string());
            }
            
            if settings.disable_webrtc {
                content.push_str("\n// Disable WebRTC\n");
                content.push_str("user_pref(\"media.peerconnection.enabled\", false);\n");
                applied_settings.push("Disable WebRTC".to_string());
            }

            if settings.disable_prefetch {
                content.push_str("\n// Disable prefetch\n");
                content.push_str("user_pref(\"network.prefetch-next\", false);\n");
                content.push_str("user_pref(\"network.dns.disablePrefetch\", true);\n");
                content.push_str("user_pref(\"network.predictor.enabled\", false);\n");
                content.push_str("user_pref(\"network.http.speculative-parallel-limit\", 0);\n");
                applied_settings.push("Disable prefetch".to_string());
            }
            
            if settings.disable_pocket {
                content.push_str("\n// Disable Pocket\n");
                content.push_str("user_pref(\"extensions.pocket.enabled\", false);\n");
                applied_settings.push("Disable Pocket".to_string());
            }
            
            if settings.enforce_https {
                content.push_str("\n// Enforce HTTPS\n");
                content.push_str("user_pref(\"dom.security.https_only_mode\", true);\n");
                content.push_str("user_pref(\"dom.security.https_only_mode_ever_enabled\", true);\n");
                applied_settings.push("Enforce HTTPS".to_string());
            }
            
            if settings.disable_cookies {
                content.push_str("\n// Strict cookie handling\n");
                content.push_str("user_pref(\"network.cookie.cookieBehavior\", 1);\n"); // 1 = Block third-party cookies
                content.push_str("user_pref(\"network.cookie.lifetimePolicy\", 2);\n"); // 2 = Clear cookies on close
                applied_settings.push("Strict cookie handling".to_string());
            }
            
            // Add fingerprinting protection based on level
            match level {
                ProtectionLevel::Standard | ProtectionLevel::Strict | ProtectionLevel::Custom => {
                    content.push_str("\n// Resist fingerprinting\n");
                    content.push_str("user_pref(\"privacy.resistFingerprinting\", true);\n");
                    content.push_str("user_pref(\"privacy.resistFingerprinting.block_mozAddonManager\", true);\n");
                    content.push_str("user_pref(\"browser.display.use_document_fonts\", 0);\n");
                    applied_settings.push("Resist fingerprinting".to_string());
                },
                _ => {} // Basic level doesn't include this
            }
            
            // Additional strict mode settings
            if level == ProtectionLevel::Strict {
                content.push_str("\n// Additional strict protections\n");
                content.push_str("user_pref(\"network.http.referer.XOriginPolicy\", 2);\n"); // 2 = Send referer only when hosts match
                content.push_str("user_pref(\"network.http.referer.XOriginTrimmingPolicy\", 2);\n"); // 2 = Trim to origin
                content.push_str("user_pref(\"webgl.disabled\", true);\n"); // Disable WebGL
                content.push_str("user_pref(\"javascript.options.baselinejit\", false);\n"); // Disable JIT compiler (more security at performance cost)
                applied_settings.push("Additional strict protections".to_string());
            }

            if settings.disable_canvas || level == ProtectionLevel::Standard || level == ProtectionLevel::Strict {
                content.push_str("\n// Disable Canvas Fingerprinting\n");
                content.push_str("user_pref(\"privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts\", true);\n");
                applied_settings.push("Disable Canvas Fingerprinting".to_string());
            }
            
            if settings.disable_webgl || level == ProtectionLevel::Strict {
                content.push_str("\n// Disable WebGL\n");
                content.push_str("user_pref(\"webgl.disabled\", true);\n");
                applied_settings.push("Disable WebGL".to_string());
            }
            
            if settings.disable_audio_api || level == ProtectionLevel::Standard || level == ProtectionLevel::Strict {
                content.push_str("\n// Disable AudioContext API\n");
                content.push_str("user_pref(\"privacy.resistFingerprinting.audioContext\", true);\n");
                applied_settings.push("Disable AudioContext API".to_string());
            }
            
            if settings.standardize_fonts || level == ProtectionLevel::Standard || level == ProtectionLevel::Strict {
                content.push_str("\n// Standardize Fonts\n");
                content.push_str("user_pref(\"font.system.whitelist\", \"\");\n");
                content.push_str("user_pref(\"browser.display.use_document_fonts\", 0);\n");
                applied_settings.push("Standardize Fonts".to_string());
            }
            
            if settings.spoof_timezone || level == ProtectionLevel::Standard || level == ProtectionLevel::Strict {
                content.push_str("\n// Spoof Timezone to UTC\n");
                content.push_str("user_pref(\"privacy.resistFingerprinting.reduceTimerPrecision\", true);\n");
                applied_settings.push("Spoof Timezone".to_string());
            }

            if settings.spoof_language || level == ProtectionLevel::Standard || level == ProtectionLevel::Strict {
                content.push_str("\n// Standardize Language to en-US\n");
                content.push_str("user_pref(\"intl.accept_languages\", \"en-US, en\");\n");
                content.push_str("user_pref(\"javascript.use_us_english_locale\", true);\n");
                applied_settings.push("Standardize Language".to_string());
            }
            
            if settings.spoof_screen_size || level == ProtectionLevel::Strict {
                content.push_str("\n// Standardize Screen Size\n");
                content.push_str("user_pref(\"privacy.resistFingerprinting.letterboxing\", true);\n");
                applied_settings.push("Standardize Screen Size".to_string());
            }
            
            if settings.spoof_user_agent || level == ProtectionLevel::Standard || level == ProtectionLevel::Strict {
                content.push_str("\n// Spoof User Agent\n");
                content.push_str("user_pref(\"general.useragent.override\", \"Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0\");\n");
                content.push_str("user_pref(\"general.platform.override\", \"Win32\");\n");
                content.push_str("user_pref(\"general.appversion.override\", \"5.0 (Windows)\");\n");
                content.push_str("user_pref(\"general.oscpu.override\", \"Windows NT 10.0; Win64; x64\");\n");
                applied_settings.push("Spoof User Agent".to_string());
            }

            // Write the user.js file
            fs::write(&user_js_path, content)?;
            
            // Log that we've applied settings to this profile
            log::info!("Applied privacy settings to Firefox profile: {}", profile_name);
        }
        
        Ok(applied_settings)
    }
    
    // Check if Firefox is already hardened
    pub fn is_hardened(&self) -> Result<bool, PrivacyError> {
        for (_, profile_path) in &self.profiles {
            let user_js_path = profile_path.join("user.js");
            
            if !user_js_path.exists() {
                return Ok(false);
            }
            
            // Check if the file contains our marker
            let file = fs::File::open(&user_js_path)?;
            let reader = BufReader::new(file);
            
            for line in reader.lines() {
                let line = line?;
                if line.contains("RustVault Privacy Protection") {
                    return Ok(true);
                }
            }
        }
        
        Ok(false)
    }
    
    // Get Firefox settings from user.js file
    pub fn get_settings(&self) -> Result<Option<FirefoxSettings>, PrivacyError> {
        for (_, profile_path) in &self.profiles {
            let user_js_path = profile_path.join("user.js");
            
            if !user_js_path.exists() {
                continue;
            }
            
            // Parse the user.js file to extract settings
            let file = fs::File::open(&user_js_path)?;
            let reader = BufReader::new(file);
            
            let mut settings = FirefoxSettings {
                disable_telemetry: false,
                enable_tracking_protection: false,
                enable_do_not_track: false,
                disable_geolocation: false,
                disable_webrtc: false,
                disable_prefetch: false,
                disable_pocket: false,
                enforce_https: false,
                disable_cookies: false,
                disable_canvas: false,
                disable_webgl: false,
                disable_audio_api: false,
                standardize_fonts: false,
                spoof_timezone: false,
                spoof_language: false,
                spoof_screen_size: false,
                spoof_user_agent: false,
            };
    
            for line in reader.lines() {
                let line = line?;
                
                // Check various settings
                if line.contains("toolkit.telemetry.enabled") && line.contains("false") {
                    settings.disable_telemetry = true;
                }
                
                if line.contains("privacy.trackingprotection.enabled") && line.contains("true") {
                    settings.enable_tracking_protection = true;
                }
                
                if line.contains("privacy.donottrackheader.enabled") && line.contains("true") {
                    settings.enable_do_not_track = true;
                }
                
                if line.contains("geo.enabled") && line.contains("false") {
                    settings.disable_geolocation = true;
                }
                
                if line.contains("media.peerconnection.enabled") && line.contains("false") {
                    settings.disable_webrtc = true;
                }
                
                if line.contains("network.prefetch-next") && line.contains("false") {
                    settings.disable_prefetch = true;
                }
                
                if line.contains("extensions.pocket.enabled") && line.contains("false") {
                    settings.disable_pocket = true;
                }
                
                if line.contains("dom.security.https_only_mode") && line.contains("true") {
                    settings.enforce_https = true;
                }
                
                if line.contains("network.cookie.cookieBehavior") && (line.contains("1") || line.contains("2")) {
                    settings.disable_cookies = true;
                }
            }
            
            return Ok(Some(settings));
        }
        
        Ok(None)
    }

    // Get comprehensive Firefox status
    pub fn get_status(&self) -> Result<FirefoxStatus, crate::privacy::PrivacyError> {
        let mut status = FirefoxStatus {
            is_installed: true,
            is_hardened: false,
            tracking_protection: false,
            do_not_track: false,
            resist_fingerprinting: false,
            canvas_protection: false,
            webgl_disabled: false,
            geolocation_disabled: false,
            webrtc_disabled: false,
            cookie_restrictions: false,
            https_only: false,
        };
        
        // Check each profile for user.js file
        for (_, profile_path) in &self.profiles {
            let user_js_path = profile_path.join("user.js");
            
            if user_js_path.exists() {
                // Parse the user.js file
                let content = std::fs::read_to_string(&user_js_path)?;
                
                // Check for RustVault marker
                if content.contains("RustVault Privacy Protection") {
                    status.is_hardened = true;
                }
                
                // Check for specific protections
                if content.contains("privacy.trackingprotection.enabled") && content.contains("true") {
                    status.tracking_protection = true;
                }
                
                if content.contains("privacy.donottrackheader.enabled") && content.contains("true") {
                    status.do_not_track = true;
                }
                
                if content.contains("privacy.resistFingerprinting") && content.contains("true") {
                    status.resist_fingerprinting = true;
                }
                
                if content.contains("privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts") && content.contains("true") {
                    status.canvas_protection = true;
                }
                
                if content.contains("webgl.disabled") && content.contains("true") {
                    status.webgl_disabled = true;
                }
                
                if content.contains("geo.enabled") && content.contains("false") {
                    status.geolocation_disabled = true;
                }
                
                if content.contains("media.peerconnection.enabled") && content.contains("false") {
                    status.webrtc_disabled = true;
                }
                
                if content.contains("network.cookie.cookieBehavior") && 
                   (content.contains("network.cookie.cookieBehavior\", 1") || content.contains("network.cookie.cookieBehavior\", 2")) {
                    status.cookie_restrictions = true;
                }
                
                if content.contains("dom.security.https_only_mode") && content.contains("true") {
                    status.https_only = true;
                }
                
                // Once we've found and analyzed a hardened profile, we can return
                if status.is_hardened {
                    return Ok(status);
                }
            }
        }
        
        Ok(status)
    }
}