use serde::{Serialize, Deserialize};
use std::str::FromStr;
use std::fmt;

use super::fingerprint::FingerprintSettings;
use super::storage::StorageSettings;
use super::network::NetworkSettings;
use super::browsers::firefox::FirefoxSettings;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, ToSchema)]
pub enum ProtectionLevel {
    Basic,
    Standard,
    Strict,
    Custom,
}

impl ProtectionLevel {
    pub fn get_default_settings(&self) -> PrivacySettings {
        match self {
            Self::Basic => PrivacySettings {
                browser_hardening: true,
                firefox: FirefoxSettings {
                    disable_telemetry: true,
                    enable_tracking_protection: true,
                    enable_do_not_track: true,
                    disable_geolocation: false,
                    disable_webrtc: false,
                    disable_prefetch: true,
                    disable_pocket: true,
                    enforce_https: true,
                    disable_cookies: false,
                    disable_canvas: false,
                    disable_webgl: false,
                    disable_audio_api: false,
                    standardize_fonts: true,
                    spoof_timezone: false,
                    spoof_language: false,
                    spoof_screen_size: false,
                    spoof_user_agent: false,
                },
                fingerprint: FingerprintSettings {
                    canvas_protection: false,
                    webgl_protection: false,
                    audio_protection: false,
                    font_protection: true,
                    accept_header_protection: false,
                    language_protection: false,
                    plugin_protection: false,
                    hardware_protection: false,
                    screen_size_protection: false,
                    timezone_protection: false,
                    user_agent_protection: false,
                },
                storage: StorageSettings {
                    cookie_management: true,
                    localstorage_clearing: false,
                    cache_management: true,
                    evercookie_mitigation: false,
                },
                network: NetworkSettings {
                    dns_privacy: false,
                    referer_control: true,
                    user_agent_management: false,
                    tls_fingerprinting_mitigation: false,
                },
            },
            Self::Standard => PrivacySettings {
                browser_hardening: true,
                firefox: FirefoxSettings {
                    disable_telemetry: true,
                    enable_tracking_protection: true,
                    enable_do_not_track: true,
                    disable_geolocation: true,
                    disable_webrtc: false,
                    disable_prefetch: true,
                    disable_pocket: true,
                    enforce_https: true,
                    disable_cookies: false,
                    disable_canvas: true,
                    disable_webgl: false,
                    disable_audio_api: true,
                    standardize_fonts: true,
                    spoof_timezone: true,
                    spoof_language: true,
                    spoof_screen_size: false,
                    spoof_user_agent: true,
                },
                fingerprint: FingerprintSettings {
                    canvas_protection: true,
                    webgl_protection: false,
                    audio_protection: true,
                    font_protection: true,
                    accept_header_protection: true,
                    language_protection: false,
                    plugin_protection: true,
                    hardware_protection: true,
                    screen_size_protection: true,
                    timezone_protection: false,
                    user_agent_protection: true,
                },
                storage: StorageSettings {
                    cookie_management: true,
                    localstorage_clearing: true,
                    cache_management: true,
                    evercookie_mitigation: true,
                },
                network: NetworkSettings {
                    dns_privacy: false,
                    referer_control: true,
                    user_agent_management: true,
                    tls_fingerprinting_mitigation: false,
                },
            },
            Self::Strict => PrivacySettings {
                browser_hardening: true,
                firefox: FirefoxSettings {
                    disable_telemetry: true,
                    enable_tracking_protection: true,
                    enable_do_not_track: true,
                    disable_geolocation: true,
                    disable_webrtc: true,
                    disable_prefetch: true,
                    disable_pocket: true,
                    enforce_https: true,
                    disable_cookies: true,
                    disable_canvas: true,
                    disable_webgl: true,
                    disable_audio_api: true,
                    standardize_fonts: true,
                    spoof_timezone: true,
                    spoof_language: true,
                    spoof_screen_size: true,
                    spoof_user_agent: true,
                },
                fingerprint: FingerprintSettings {
                    canvas_protection: true,
                    webgl_protection: true,
                    audio_protection: true,
                    font_protection: true,
                    accept_header_protection: true,
                    language_protection: true,
                    plugin_protection: true,
                    hardware_protection: true,
                    screen_size_protection: true,
                    timezone_protection: true,
                    user_agent_protection: true,
                },
                storage: StorageSettings {
                    cookie_management: true,
                    localstorage_clearing: true,
                    cache_management: true,
                    evercookie_mitigation: true,
                },
                network: NetworkSettings {
                    dns_privacy: true,
                    referer_control: true,
                    user_agent_management: true,
                    tls_fingerprinting_mitigation: true,
                },
            },
            Self::Custom => PrivacySettings {
                ..Self::Standard.get_default_settings()
            },
        }
    }
}

impl fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Basic => "Basic",
            Self::Standard => "Standard",
            Self::Strict => "Strict",
            Self::Custom => "Custom",
        };
        write!(f, "{s}")
    }
}

impl FromStr for ProtectionLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "basic" => Ok(Self::Basic),
            "standard" => Ok(Self::Standard),
            "strict" => Ok(Self::Strict),
            "custom" => Ok(Self::Custom),
            _ => Err(format!("Invalid protection level: {}", s)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct PrivacySettings {
    pub browser_hardening: bool,
    pub firefox: FirefoxSettings,
    pub fingerprint: FingerprintSettings,
    pub storage: StorageSettings,
    pub network: NetworkSettings,
}
