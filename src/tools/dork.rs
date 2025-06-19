// src/tools/dork.rs
use std::error::Error;

pub struct GoogleDorkBuilder;

impl GoogleDorkBuilder {
    pub fn new() -> Self {
        Self {}
    }
    
    pub fn generate_dork(&self, 
        search_type: &str, 
        keywords: &[String], 
        exclude_terms: Option<&[String]>, 
        site_restrictions: Option<&[String]>, 
        file_types: Option<&[String]>,
        date_range: Option<(&str, Option<&str>)>
    ) -> Result<(String, String), Box<dyn Error>> {
        let mut dork_query = String::new();
        let mut explanation = String::new();
        
        // Add keywords
        let keyword_str = keywords.join(" ");
        dork_query.push_str(&keyword_str);
        explanation.push_str(&format!("Search for: {}\n", keyword_str));
        
        // Add search type-specific modifiers
        match search_type {
            "site" => {
                if let Some(sites) = site_restrictions {
                    for site in sites {
                        dork_query.push_str(&format!(" site:{}", site));
                        explanation.push_str(&format!("Restrict search to website: {}\n", site));
                    }
                } else {
                    return Err("Site search type requires site restrictions".into());
                }
            },
            "filetype" => {
                if let Some(types) = file_types {
                    for file_type in types {
                        dork_query.push_str(&format!(" filetype:{}", file_type));
                        explanation.push_str(&format!("Search for file type: {}\n", file_type));
                    }
                } else {
                    return Err("Filetype search type requires file types".into());
                }
            },
            "intext" => {
                for keyword in keywords {
                    dork_query = format!("intext:{} {}", keyword, dork_query);
                    explanation.push_str(&format!("Find pages containing '{}' in the text\n", keyword));
                }
            },
            "inurl" => {
                for keyword in keywords {
                    dork_query = format!("inurl:{} {}", keyword, dork_query);
                    explanation.push_str(&format!("Find pages with '{}' in the URL\n", keyword));
                }
            },
            "intitle" => {
                for keyword in keywords {
                    dork_query = format!("intitle:{} {}", keyword, dork_query);
                    explanation.push_str(&format!("Find pages with '{}' in the title\n", keyword));
                }
            },
            "cache" => {
                if let Some(sites) = site_restrictions {
                    for site in sites {
                        dork_query = format!("cache:{} {}", site, dork_query);
                        explanation.push_str(&format!("Show Google's cached version of {}\n", site));
                    }
                } else {
                    return Err("Cache search type requires site restrictions".into());
                }
            },
            "advanced" => {
                // Just use the keywords directly for advanced users
                explanation.push_str("Advanced search: Using raw query as provided\n");
            },
            _ => {
                return Err(format!("Unknown search type: {}", search_type).into());
            }
        }
        
        // Add site restrictions if not already added in site search type
        if search_type != "site" && search_type != "cache" {
            if let Some(sites) = site_restrictions {
                for site in sites {
                    dork_query.push_str(&format!(" site:{}", site));
                    explanation.push_str(&format!("Restrict search to website: {}\n", site));
                }
            }
        }
        
        // Add file type restrictions if not already added in filetype search type
        if search_type != "filetype" {
            if let Some(types) = file_types {
                for file_type in types {
                    dork_query.push_str(&format!(" filetype:{}", file_type));
                    explanation.push_str(&format!("Search for file type: {}\n", file_type));
                }
            }
        }
        
        // Add exclude terms
        if let Some(excludes) = exclude_terms {
            for term in excludes {
                dork_query.push_str(&format!(" -{}", term));
                explanation.push_str(&format!("Exclude pages containing: {}\n", term));
            }
        }
        
        // Add date range
        if let Some((start_date, end_date)) = date_range {
            dork_query.push_str(&format!(" after:{}", start_date));
            explanation.push_str(&format!("Find pages published after: {}\n", start_date));
            
            if let Some(end) = end_date {
                dork_query.push_str(&format!(" before:{}", end));
                explanation.push_str(&format!("Find pages published before: {}\n", end));
            }
        }
        
        // Add security notice
        explanation.push_str("\nIMPORTANT: Remember to use this responsibly and ethically. Never use for unauthorized access or illegal activities.");
        
        Ok((dork_query, explanation))
    }
}