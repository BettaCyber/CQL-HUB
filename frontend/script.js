class CQLHub {
    constructor() {
        this.queries = [];
        this.filteredQueries = [];
        this.currentFilters = {
            search: '',
            tag: '',
            mitreId: '',
            logSource: '',
            csRequiredModules: []
        };
        
        this.selectedFalconRegion = '';

        this.falconUrls = {
            US1: 'https://falcon.crowdstrike.com//investigate/search?query=',
            US2: 'https://falcon.us-2.crowdstrike.com//investigate/search?query=',
            EU1: 'https://falcon.eu-1.crowdstrike.com//investigate/search?query='
        };

        this.currentQuery = null; // Store current query for modal

        // Pagination properties
        this.currentPage = 1;
        this.queriesPerPage = 12;
        this.displayedQueries = [];

        // Sorting property
        this.currentSort = 'desc'; // Default to newest first

        // Runtime configuration
        this.appConfig = window.APP_CONFIG || {};
        this.apiBaseUrl = this.resolveApiBaseUrl();
        this.githubRepoUrl = this.resolveGithubRepoUrl();
        this.githubRawBaseUrl = this.githubRepoUrl.replace('https://github.com/', 'https://raw.githubusercontent.com/');

        // Lookup files properties
        this.lookupFiles = [];
        this.filteredLookupFiles = [];
        this.displayedLookupFiles = [];
        this.lookupCurrentPage = 1;
        this.lookupPerPage = 12;
        this.lookupFilters = { search: '' };
        this.queriesStorageKey = 'cqlhub_cached_queries_v1';
        this.lookupFilesStorageKey = 'cqlhub_cached_lookups_v1';
        this.isLoadingQueries = false;
        this.isLoadingLookupFiles = false;
        this.isUsingCachedQueries = false;
        this.isUsingCachedLookupFiles = false;

        // Cross-reference maps
        this.queryToLookups = {};
        this.lookupToQueries = {};

        // Lookup file contribution state
        this.csvFileContent = null;
        this.csvFileName = null;

        // CrowdStrike pre-supplied lookup files
        this.preSuppliedLookupFiles = [
            'falcon/investigate/zta_signals.csv',
            'falcon/investigate/vendorid.csv',
            'falcon/ngsiem-partner-veeam/veeam_vbr_session_states_lookup.csv',
            'falcon/ngsiem-partner-veeam/veeam_vbr_operation_names_lookup.csv',
            'falcon/ngsiem-partner-veeam/veeam_vbr_job_types_lookup.csv',
            'falcon/ngsiem-partner-veeam/veeam_vbr_events_lookup.csv',
            'falcon/ngsiem-partner-veeam/veeam_vbr_action_results_lookup.csv',
            'falcon/ngsiem-content/tor_domains.csv',
            'falcon/ngsiem-content/suspicious_user_agents.csv',
            'falcon/ngsiem-content/suspicious_top_level_domains.csv',
            'falcon/ngsiem-content/suspicious_file_extension.csv',
            'falcon/investigate/statusdecimal.csv',
            'falcon/investigate/sid_list.csv',
            'falcon/investigate/service-names-port-numbers.csv',
            'falcon/helper/sensors_support_info.csv',
            'falcon/investigate/RegOperation.csv',
            'falcon/investigate/recon_apps.csv',
            'falcon/investigate/ProductType.csv',
            'falcon/investigate/PolicyTag.csv',
            'falcon/investigate/patterndisposition.csv',
            'falcon/ngsiem-content/paste_bin_sites.csv',
            'falcon/investigate/not_recon_apps.csv',
            'falcon/ngsiem-content-crt/ngsiem_rule_templates.csv',
            'falcon/ngsiem-content-crt/ngsiem_correlation_rule_templates.csv',
            'falcon/investigate/mobile_mitr_patterns.csv',
            'falcon/investigate/mobile_attack_definitions.csv',
            'epp/lookups/MitreMappings-ecs.csv',
            'falcon/investigate/mitre_obj_tactic.csv',
            'epp/lookups/MicrosoftWindowsEventCategorization.csv',
            'falcon/helper/mappings.csv',
            'falcon/investigate/macprefix.csv',
            'falcon/investigate/LogonType.csv',
            'falcon/investigate/logoninfo.csv',
            'falcon/ngsiem-content-et/ingress_nginx_controller_hashes.csv',
            'falcon/investigate/grouprid_wingroup.csv',
            'falcon/investigate/geo_mappings.csv',
            'falcon/ngsiem-content-ai/GenAIKeywords.csv',
            'falcon/investigate/forescout_apps.csv',
            'falcon/investigate/firmware_vulnerabilities.csv',
            'falcon/ngsiem/fc_supported_data_sources.csv',
            'falconUserIdentityContext.csv',
            'epp/lookups/FalconEventMappings.csv',
            'falconEntityEnrichment.csv',
            'falcon/investigate/exclude_patterns.csv',
            'falcon/ngsiem-content/directory_traversal_url.csv',
            'falcon/investigate/detection_name_cleaned.csv',
            'falcon/investigate/detect_patterns.csv',
            'cs_lookups_c_rules.csv',
            'falcon/ngsiem-content/crypto_mining_domains.csv',
            'falcon/investigate/cross_platform_recon_apps.csv',
            'falcon/ngsiem/corelight_ssh_inference_lookup.csv',
            'falcon/ngsiem/corelight_inferences_description.csv',
            'falcon/ngsiem/corelight_geo_countries.csv',
            'falcon/ngsiem/corelight_aggregations_enrichment.csv',
            'falcon/investigate/common_processes.csv',
            'falcon/ngsiem-content/command_injection_characters.csv',
            'falcon/ngsiem-content/command_injection.csv',
            'falcon/investigate/cloud_providers.csv',
            'falcon/investigate/cloud_instance_types.csv',
            'falcon/investigate/chassis.csv',
            'falcon/investigate/bios_prevalence.csv',
            'epp/lookups/AWSCloudTrailResourceMappings.csv',
            'falcon/investigate/AsepValue.csv',
            'falcon/investigate/AsepClass.csv',
            'falcon/ngsiem/AnnotationDescriptions.csv',
            'aid_master_main.csv',
            'aid_master_details.csv'
        ];

        // Navigation state
        this.currentView = 'queries';

        this.init();
    }

    resolveApiBaseUrl() {
        const configuredValue = (this.appConfig.API_BASE_URL || '').trim();
        if (configuredValue) {
            return configuredValue.replace(/\/$/, '');
        }

        const hostname = window.location.hostname;
        const isLocalHost = hostname === 'localhost' || hostname === '127.0.0.1';
        if (isLocalHost) {
            return 'http://localhost:8002';
        }

        return `${window.location.origin}/api`;
    }

    resolveGithubRepoUrl() {
        const configuredValue = (this.appConfig.GITHUB_REPO_URL || '').trim();
        if (configuredValue) {
            return configuredValue.replace(/\/$/, '');
        }

        return 'https://github.com/BettaCyber/CQL-HUB';
    }

    init() {
        this.loadRegionFromCookie();
        this.initNavigation();
        this.bindEvents();
        this.hydrateCachedData();
        this.loadQueries();
        this.loadLookupFiles();
    }

    hydrateCachedData() {
        const cachedQueries = this.readJsonStorage(this.queriesStorageKey, []);
        if (Array.isArray(cachedQueries) && cachedQueries.length > 0) {
            this.queries = cachedQueries;
            this.filteredQueries = [...cachedQueries];
            this.applySorting();
            this.populateFiltersFromAllQueries();
            this.displayQueries();
        }

        const cachedLookupFiles = this.readJsonStorage(this.lookupFilesStorageKey, []);
        if (Array.isArray(cachedLookupFiles) && cachedLookupFiles.length > 0) {
            this.lookupFiles = cachedLookupFiles;
            this.filteredLookupFiles = [...cachedLookupFiles];
            this.buildCrossReferences();
            this.displayLookupFiles();
        }
    }

    readJsonStorage(key, fallbackValue) {
        try {
            const rawValue = window.localStorage.getItem(key);
            if (!rawValue) return fallbackValue;
            return JSON.parse(rawValue);
        } catch (error) {
            console.warn(`Failed to read cached data for ${key}:`, error);
            return fallbackValue;
        }
    }

    writeJsonStorage(key, value) {
        try {
            window.localStorage.setItem(key, JSON.stringify(value));
        } catch (error) {
            console.warn(`Failed to write cached data for ${key}:`, error);
        }
    }

    loadRegionFromCookie() {
        const savedRegion = this.getCookie('falconRegion');
        if (savedRegion && this.falconUrls[savedRegion]) {
            this.selectedFalconRegion = savedRegion;
            // Update the custom dropdown display when DOM is ready
            setTimeout(() => {
                const button = document.getElementById('falconRegionFilterButton');
                const dropdown = document.getElementById('falconRegionFilterDropdown');
                if (button && dropdown) {
                    const textSpan = button.querySelector('.select-text');
                    const selectedOption = dropdown.querySelector(`[data-value="${savedRegion}"]`);
                    if (selectedOption) {
                        textSpan.textContent = selectedOption.textContent;
                        dropdown.querySelectorAll('.select-option').forEach(opt => opt.classList.remove('selected'));
                        selectedOption.classList.add('selected');
                    }
                }
            }, 0);
        }
    }

    bindEvents() {
        const searchInput = document.getElementById('searchInput');
        const searchButton = document.getElementById('searchButton');
        const tagFilterButton = document.getElementById('tagFilterButton');
        const mitreIdFilterButton = document.getElementById('mitreIdFilterButton');
        const logSourceFilterButton = document.getElementById('logSourceFilterButton');
        const csRequiredModulesButton = document.getElementById('csRequiredModulesButton');
        const perPageSelectButton = document.getElementById('perPageSelectButton');
        const falconRegionFilterButton = document.getElementById('falconRegionFilterButton');
        const clearFilters = document.getElementById('clearFilters');

        searchButton.addEventListener('click', () => this.handleSearch());
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handleSearch();
        });
        searchInput.addEventListener('input', (e) => {
            this.currentFilters.search = e.target.value;
            this.debounceFilter();
        });

        // Custom select dropdown events
        tagFilterButton.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleCustomSelect('tagFilter');
        });

        mitreIdFilterButton.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleCustomSelect('mitreIdFilter');
        });

        logSourceFilterButton.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleCustomSelect('logSourceFilter');
        });

        perPageSelectButton.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleStandaloneSelect('perPageSelect');
        });

        const sortSelectButton = document.getElementById('sortSelectButton');
        sortSelectButton.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleStandaloneSelect('sortSelect');
        });

        falconRegionFilterButton.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleStandaloneSelect('falconRegionFilter');
        });

        // Custom multiselect dropdown events
        csRequiredModulesButton.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleMultiSelectDropdown();
        });

        // Close dropdowns when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.custom-multiselect')) {
                this.closeMultiSelectDropdown();
            }
            if (!e.target.closest('.custom-select')) {
                this.closeAllCustomSelects();
                this.closeAllStandaloneSelects();
            }
        });

        // Falcon region filter handled above

        clearFilters.addEventListener('click', () => this.clearAllFilters());

        // YAML Builder button event listener
        const yamlBuilderButton = document.getElementById('yamlBuilderButton');
        yamlBuilderButton.addEventListener('click', () => this.openYamlBuilder());

        // Pagination event listeners
        this.bindPaginationEvents();

        // Modal event listeners
        this.bindModalEvents();
        this.bindYamlBuilderEvents();

        // Lookup file events
        const lookupSearchInput = document.getElementById('lookupSearchInput');
        const lookupSearchButton = document.getElementById('lookupSearchButton');
        const lookupClearFilters = document.getElementById('lookupClearFilters');
        const lookupPerPageSelectButton = document.getElementById('lookupPerPageSelectButton');

        if (lookupSearchButton) {
            lookupSearchButton.addEventListener('click', () => this.handleLookupSearch());
        }
        if (lookupSearchInput) {
            lookupSearchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.handleLookupSearch();
            });
            lookupSearchInput.addEventListener('input', (e) => {
                this.lookupFilters.search = e.target.value;
                this.debounceLookupFilter();
            });
        }
        if (lookupClearFilters) {
            lookupClearFilters.addEventListener('click', () => this.clearLookupFilters());
        }
        if (lookupPerPageSelectButton) {
            lookupPerPageSelectButton.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggleStandaloneSelect('lookupPerPageSelect');
            });
        }

        // Lookup pagination events
        this.bindLookupPaginationEvents();

        // Lookup modal events
        this.bindLookupModalEvents();
    }

    debounceFilter() {
        clearTimeout(this.filterTimeout);
        this.filterTimeout = setTimeout(() => this.filterQueries(), 300);
    }

    handleSearch() {
        const searchInput = document.getElementById('searchInput');
        this.currentFilters.search = searchInput.value;
        this.filterQueries();
    }

    async loadQueries() {
        this.isLoadingQueries = true;
        this.displayQueries();
        try {
            const response = await fetch(`${this.apiBaseUrl}/queries`);
            if (!response.ok) {
                throw new Error(`Query request failed with status ${response.status}`);
            }
            const data = await response.json();
            
            // Parse the new format - extract parsed_content from each query
            this.queries = [];
            if (data.queries) {
                Object.keys(data.queries).forEach(key => {
                    const queryData = data.queries[key];
                    if (queryData.parsed_content) {
                        // Add filename for reference and store explanation
                        const query = {
                            ...queryData.parsed_content,
                            filename: queryData.filename || key,
                            created_date: queryData.created_date, // Store creation date
                            explanation: queryData.parsed_content.explanation // Store for future use
                        };
                        // Fix escaped quotes in all string properties
                        this.unescapeQuotes(query);
                        this.queries.push(query);
                    }
                });
            }

            this.filteredQueries = [...this.queries];
            this.isUsingCachedQueries = false;
            this.writeJsonStorage(this.queriesStorageKey, this.queries);
            this.applySorting(); // Apply initial sorting
            this.populateFiltersFromAllQueries();
            this.displayQueries();
            this.buildCrossReferences();

            // Re-render lookup cards if they loaded first (so "Used by" counts are shown)
            if (this.lookupFiles.length > 0) {
                this.displayLookupFiles();
            }

            this.resolveDeepLink();
        } catch (error) {
            console.error('Error loading queries:', error);
            if (this.queries.length > 0) {
                this.filteredQueries = [...this.queries];
                this.isUsingCachedQueries = true;
                this.applySorting();
                this.populateFiltersFromAllQueries();
                this.displayQueries();
                return;
            }

            const cachedQueries = this.readJsonStorage(this.queriesStorageKey, []);
            if (Array.isArray(cachedQueries) && cachedQueries.length > 0) {
                this.queries = cachedQueries;
                this.filteredQueries = [...cachedQueries];
                this.isUsingCachedQueries = true;
                this.applySorting();
                this.populateFiltersFromAllQueries();
                this.displayQueries();
                return;
            }

            this.displayError('Failed to load queries from API. Please check your connection.');
        } finally {
            this.isLoadingQueries = false;
            this.displayQueries();
            this.updateCachedDataBanner();
        }
    }

    populateFilters() {
        // Get available options for each filter type based on current filtering state
        const availableTags = this.getAvailableFilterOptions('tag');
        const availableMitreIds = this.getAvailableFilterOptions('mitreId');
        const availableLogSources = this.getAvailableFilterOptions('logSource');
        const availableCSRequiredModules = this.getAvailableFilterOptions('csRequiredModules');

        this.populateCustomSelect('tagFilter', availableTags.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())), 'All Tags');
        this.populateCustomSelect('mitreIdFilter', availableMitreIds.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())), 'All MITRE IDs');
        this.populateCustomSelect('logSourceFilter', availableLogSources.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())), 'All Log Sources');
        this.populateMultiSelect('csRequiredModulesFilter', availableCSRequiredModules.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())));
    }

    getAvailableFilterOptions(filterType) {
        const options = new Map();
        
        // For each possible option, check if selecting it would return any results
        this.queries.forEach(query => {
            let fieldValues = [];
            
            // Get the field values for this filter type
            switch (filterType) {
                case 'tag':
                    fieldValues = query.tags || [];
                    break;
                case 'mitreId':
                    fieldValues = query.mitre_ids || [];
                    break;
                case 'logSource':
                    fieldValues = query.log_sources || [];
                    break;
                case 'csRequiredModules':
                    fieldValues = query.cs_required_modules || [];
                    break;
            }
            
            // For each value in this field, check if it would produce results
            fieldValues.forEach(value => {
                const lowerCase = value.toLowerCase();
                if (!options.has(lowerCase) && this.wouldFilterProduceResults(filterType, value)) {
                    options.set(lowerCase, value);
                }
            });
        });
        
        return Array.from(options.values());
    }

    wouldFilterProduceResults(filterType, filterValue) {
        // Create a temporary filter state with the proposed filter
        const tempFilters = { ...this.currentFilters };
        tempFilters[filterType] = filterValue;
        
        // Check if any queries would match with this filter combination
        return this.queries.some(query => {
            // Apply search filter
            if (tempFilters.search) {
                const searchLower = tempFilters.search.toLowerCase();
                const searchableText = [
                    query.name,
                    query.description,
                    query.author,
                    ...(query.mitre_ids || []),
                    ...(query.tags || []),
                    query.cql
                ].join(' ').toLowerCase();
                
                if (!searchableText.includes(searchLower)) {
                    return false;
                }
            }

            // Apply tag filter
            if (tempFilters.tag) {
                if (!query.tags || !query.tags.some(tag => tag.toLowerCase() === tempFilters.tag.toLowerCase())) {
                    return false;
                }
            }

            // Apply MITRE ID filter
            if (tempFilters.mitreId) {
                if (!query.mitre_ids || !query.mitre_ids.some(id => id.toLowerCase() === tempFilters.mitreId.toLowerCase())) {
                    return false;
                }
            }

            // Apply log source filter
            if (tempFilters.logSource) {
                if (!query.log_sources || !query.log_sources.some(source => source.toLowerCase() === tempFilters.logSource.toLowerCase())) {
                    return false;
                }
            }

            return true;
        });
    }

    populateFiltersFromAllQueries() {
        // This method populates filters from all queries (used on initial load and clear filters)
        const tags = new Map();
        const mitreIds = new Map();
        const logSources = new Map();
        const csRequiredModules = new Map();

        this.queries.forEach(query => {
            if (query.tags) {
                query.tags.forEach(tag => {
                    const lowerCase = tag.toLowerCase();
                    if (!tags.has(lowerCase)) {
                        tags.set(lowerCase, tag);
                    }
                });
            }
            if (query.mitre_ids) {
                query.mitre_ids.forEach(id => {
                    const lowerCase = id.toLowerCase();
                    if (!mitreIds.has(lowerCase)) {
                        mitreIds.set(lowerCase, id);
                    }
                });
            }
            if (query.log_sources) {
                query.log_sources.forEach(source => {
                    const lowerCase = source.toLowerCase();
                    if (!logSources.has(lowerCase)) {
                        logSources.set(lowerCase, source);
                    }
                });
            }
            if (query.cs_required_modules) {
                query.cs_required_modules.forEach(module => {
                    const lowerCase = module.toLowerCase();
                    if (!csRequiredModules.has(lowerCase)) {
                        csRequiredModules.set(lowerCase, module);
                    }
                });
            }
        });

        this.populateCustomSelect('tagFilter', Array.from(tags.values()).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())), 'All Tags');
        this.populateCustomSelect('mitreIdFilter', Array.from(mitreIds.values()).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())), 'All MITRE IDs');
        this.populateCustomSelect('logSourceFilter', Array.from(logSources.values()).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())), 'All Log Sources');
        this.populateMultiSelect('csRequiredModulesFilter', Array.from(csRequiredModules.values()).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())));
    }

    populateSelect(selectId, options) {
        const select = document.getElementById(selectId);
        const currentValue = select.value;
        
        // Clear existing options except the first one
        while (select.children.length > 1) {
            select.removeChild(select.lastChild);
        }

        options.forEach(option => {
            const optionElement = document.createElement('option');
            optionElement.value = option;
            optionElement.textContent = option;
            select.appendChild(optionElement);
        });

        // Restore previous selection if it still exists
        if (options.includes(currentValue)) {
            select.value = currentValue;
        }
    }

    populateMultiSelect(selectId, options) {
        // For the custom multiselect dropdown
        if (selectId === 'csRequiredModulesFilter') {
            this.populateCustomMultiSelect(options);
            return;
        }
        
        const select = document.getElementById(selectId);
        const currentValues = Array.from(select.selectedOptions).map(option => option.value);
        
        // Clear existing options
        select.innerHTML = '';

        options.forEach(option => {
            const optionElement = document.createElement('option');
            optionElement.value = option;
            optionElement.textContent = option;
            select.appendChild(optionElement);
        });

        // Restore previous selections if they still exist
        Array.from(select.options).forEach(option => {
            if (currentValues.includes(option.value)) {
                option.selected = true;
            }
        });
    }

    populateCustomMultiSelect(options) {
        const dropdown = document.getElementById('csRequiredModulesDropdown');
        const currentValues = this.currentFilters.csRequiredModules;
        
        dropdown.innerHTML = '';

        options.forEach(option => {
            const optionDiv = document.createElement('div');
            optionDiv.className = 'multiselect-option';
            
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.value = option;
            checkbox.id = `cs-module-${option}`;
            checkbox.checked = currentValues.includes(option);
            
            const label = document.createElement('label');
            label.htmlFor = checkbox.id;
            label.textContent = option;
            
            optionDiv.appendChild(checkbox);
            optionDiv.appendChild(label);
            dropdown.appendChild(optionDiv);
            
            // Add event listener for checkbox change
            checkbox.addEventListener('change', (e) => {
                e.stopPropagation();
                this.handleMultiSelectChange();
            });
            
            // Allow clicking anywhere on the option div to toggle checkbox
            optionDiv.addEventListener('click', (e) => {
                e.stopPropagation(); // Prevent dropdown from closing
                if (e.target !== checkbox && e.target !== label) {
                    // Only toggle if not clicking directly on checkbox or label
                    checkbox.checked = !checkbox.checked;
                    this.handleMultiSelectChange();
                } else if (e.target === label) {
                    // If clicking on label, let it naturally toggle the checkbox
                    // The checkbox change event will handle the rest
                }
            });
        });

        this.updateMultiSelectButtonText();
    }

    toggleMultiSelectDropdown() {
        const button = document.getElementById('csRequiredModulesButton');
        const dropdown = document.getElementById('csRequiredModulesDropdown');
        
        const isOpen = dropdown.classList.contains('show');
        
        if (isOpen) {
            // Close this dropdown
            this.closeMultiSelectDropdown();
        } else {
            // Close all other dropdowns first
            this.closeAllCustomSelects();
            this.closeAllStandaloneSelects();
            
            // Open this dropdown
            dropdown.classList.add('show');
            button.classList.add('active');
        }
    }

    closeMultiSelectDropdown() {
        const button = document.getElementById('csRequiredModulesButton');
        const dropdown = document.getElementById('csRequiredModulesDropdown');
        
        dropdown.classList.remove('show');
        button.classList.remove('active');
    }

    handleMultiSelectChange() {
        const dropdown = document.getElementById('csRequiredModulesDropdown');
        const checkboxes = dropdown.querySelectorAll('input[type="checkbox"]');
        
        this.currentFilters.csRequiredModules = Array.from(checkboxes)
            .filter(checkbox => checkbox.checked)
            .map(checkbox => checkbox.value);
        
        this.updateMultiSelectButtonText();
        this.filterQueries();
    }

    updateMultiSelectButtonText() {
        const button = document.getElementById('csRequiredModulesButton');
        const textSpan = button.querySelector('.multiselect-text');
        const selectedCount = this.currentFilters.csRequiredModules.length;
        
        if (selectedCount === 0) {
            textSpan.textContent = 'All Modules';
        } else if (selectedCount === 1) {
            textSpan.textContent = this.currentFilters.csRequiredModules[0];
        } else {
            textSpan.textContent = `${selectedCount} modules selected`;
        }
    }

    populateCustomSelect(filterId, options, defaultText) {
        const dropdown = document.getElementById(filterId + 'Dropdown');
        const button = document.getElementById(filterId + 'Button');
        const textSpan = button.querySelector('.select-text');
        
        // Get current value
        const currentValue = this.getCurrentFilterValue(filterId);
        
        dropdown.innerHTML = '';

        // Add default "All" option
        const defaultOption = document.createElement('div');
        defaultOption.className = 'select-option';
        defaultOption.textContent = defaultText;
        defaultOption.dataset.value = '';
        dropdown.appendChild(defaultOption);

        // Add other options
        options.forEach(option => {
            const optionDiv = document.createElement('div');
            optionDiv.className = 'select-option';
            optionDiv.textContent = option;
            optionDiv.dataset.value = option;
            dropdown.appendChild(optionDiv);
        });

        // Mark selected option and update button text
        const allOptions = dropdown.querySelectorAll('.select-option');
        allOptions.forEach(option => {
            if (option.dataset.value === currentValue) {
                option.classList.add('selected');
                textSpan.textContent = option.textContent;
            }
            
            option.addEventListener('click', (e) => {
                e.stopPropagation();
                this.selectCustomOption(filterId, option.dataset.value, option.textContent);
            });
        });

        // If no current selection, show default
        if (!currentValue) {
            textSpan.textContent = defaultText;
            allOptions[0].classList.add('selected');
        }
    }

    getCurrentFilterValue(filterId) {
        switch(filterId) {
            case 'tagFilter': return this.currentFilters.tag;
            case 'mitreIdFilter': return this.currentFilters.mitreId;
            case 'logSourceFilter': return this.currentFilters.logSource;
            default: return '';
        }
    }

    toggleCustomSelect(filterId) {
        const button = document.getElementById(filterId + 'Button');
        const dropdown = document.getElementById(filterId + 'Dropdown');
        
        const isOpen = dropdown.classList.contains('show');
        
        if (isOpen) {
            // Close this dropdown
            dropdown.classList.remove('show');
            button.classList.remove('active');
        } else {
            // Close other dropdowns first
            this.closeAllCustomSelects();
            this.closeAllStandaloneSelects();
            this.closeMultiSelectDropdown();
            
            // Open this dropdown
            dropdown.classList.add('show');
            button.classList.add('active');
        }
    }

    closeAllCustomSelects() {
        const selects = ['tagFilter', 'mitreIdFilter', 'logSourceFilter'];
        selects.forEach(filterId => {
            const button = document.getElementById(filterId + 'Button');
            const dropdown = document.getElementById(filterId + 'Dropdown');
            if (button && dropdown) {
                dropdown.classList.remove('show');
                button.classList.remove('active');
            }
        });
    }

    selectCustomOption(filterId, value, text) {
        const button = document.getElementById(filterId + 'Button');
        const dropdown = document.getElementById(filterId + 'Dropdown');
        const textSpan = button.querySelector('.select-text');
        
        // Update UI
        textSpan.textContent = text;
        
        // Update selected state
        dropdown.querySelectorAll('.select-option').forEach(option => {
            option.classList.remove('selected');
        });
        dropdown.querySelector(`[data-value="${value}"]`).classList.add('selected');
        
        // Update filter value
        switch(filterId) {
            case 'tagFilter':
                this.currentFilters.tag = value;
                this.filterQueries();
                break;
            case 'mitreIdFilter':
                this.currentFilters.mitreId = value;
                this.filterQueries();
                break;
            case 'logSourceFilter':
                this.currentFilters.logSource = value;
                this.filterQueries();
                break;
        }
        
        // Close dropdown
        dropdown.classList.remove('show');
        button.classList.remove('active');
    }

    clearCustomSelect(filterId, defaultText) {
        const button = document.getElementById(filterId + 'Button');
        const dropdown = document.getElementById(filterId + 'Dropdown');
        
        if (button && dropdown) {
            const textSpan = button.querySelector('.select-text');
            textSpan.textContent = defaultText;
            
            // Remove selected state from all options
            dropdown.querySelectorAll('.select-option').forEach(option => {
                option.classList.remove('selected');
            });
            
            // Select the first (default) option
            const defaultOption = dropdown.querySelector('.select-option');
            if (defaultOption) {
                defaultOption.classList.add('selected');
            }
            
            // Close dropdown
            dropdown.classList.remove('show');
            button.classList.remove('active');
        }
    }

    // Standalone select methods (for styling only, not filtering)
    toggleStandaloneSelect(selectId) {
        const button = document.getElementById(selectId + 'Button');
        const dropdown = document.getElementById(selectId + 'Dropdown');
        
        if (button && dropdown) {
            const isOpen = dropdown.classList.contains('show');
            
            if (isOpen) {
                // Close this dropdown
                dropdown.classList.remove('show');
                button.classList.remove('active');
            } else {
                // Close all other dropdowns first
                this.closeAllCustomSelects();
                this.closeAllStandaloneSelects();
                this.closeMultiSelectDropdown();
                
                // Open this dropdown
                dropdown.classList.add('show');
                button.classList.add('active');
                
                // Bind option click events if not already bound
                this.bindStandaloneSelectOptions(selectId);
            }
        }
    }

    closeAllStandaloneSelects() {
        const selects = ['perPageSelect', 'sortSelect', 'falconRegionFilter', 'lookupPerPageSelect'];
        selects.forEach(selectId => {
            const button = document.getElementById(selectId + 'Button');
            const dropdown = document.getElementById(selectId + 'Dropdown');
            if (button && dropdown) {
                dropdown.classList.remove('show');
                button.classList.remove('active');
            }
        });
    }

    bindStandaloneSelectOptions(selectId) {
        const dropdown = document.getElementById(selectId + 'Dropdown');
        const options = dropdown.querySelectorAll('.select-option');
        
        options.forEach(option => {
            // Remove existing event listeners to avoid duplicates
            option.replaceWith(option.cloneNode(true));
        });
        
        // Re-query after cloning
        const newOptions = dropdown.querySelectorAll('.select-option');
        newOptions.forEach(option => {
            option.addEventListener('click', (e) => {
                e.stopPropagation();
                this.selectStandaloneOption(selectId, option.dataset.value, option.textContent);
            });
        });
    }

    selectStandaloneOption(selectId, value, text) {
        const button = document.getElementById(selectId + 'Button');
        const dropdown = document.getElementById(selectId + 'Dropdown');
        const textSpan = button.querySelector('.select-text');
        
        // Update UI
        textSpan.textContent = text;
        
        // Update selected state
        dropdown.querySelectorAll('.select-option').forEach(option => {
            option.classList.remove('selected');
        });
        dropdown.querySelector(`[data-value="${value}"]`).classList.add('selected');
        
        // Handle specific functionality
        if (selectId === 'perPageSelect') {
            this.queriesPerPage = value === 'all' ? 'all' : parseInt(value);
            this.currentPage = 1; // Reset to first page
            this.displayQueries();
        } else if (selectId === 'sortSelect') {
            this.currentSort = value;
            this.currentPage = 1; // Reset to first page
            this.applySorting();
            this.displayQueries();
        } else if (selectId === 'falconRegionFilter') {
            this.selectedFalconRegion = value;
            this.setCookie('falconRegion', value);
            this.updateFalconButtonsState();
        } else if (selectId === 'lookupPerPageSelect') {
            this.lookupPerPage = value === 'all' ? 'all' : parseInt(value);
            this.lookupCurrentPage = 1;
            this.displayLookupFiles();
        }

        // Close dropdown
        dropdown.classList.remove('show');
        button.classList.remove('active');
    }

    filterQueries() {
        this.filteredQueries = this.queries.filter(query => {
            // Search filter
            if (this.currentFilters.search) {
                const searchLower = this.currentFilters.search.toLowerCase();
                const searchableText = [
                    query.name,
                    query.description,
                    query.author,
                    ...(query.mitre_ids || []),
                    ...(query.tags || []),
                    query.cql
                ].join(' ').toLowerCase();
                
                if (!searchableText.includes(searchLower)) {
                    return false;
                }
            }

            // Tag filter
            if (this.currentFilters.tag) {
                if (!query.tags || !query.tags.some(tag => tag.toLowerCase() === this.currentFilters.tag.toLowerCase())) {
                    return false;
                }
            }

            // MITRE ID filter
            if (this.currentFilters.mitreId) {
                if (!query.mitre_ids || !query.mitre_ids.some(id => id.toLowerCase() === this.currentFilters.mitreId.toLowerCase())) {
                    return false;
                }
            }

            // Log source filter
            if (this.currentFilters.logSource) {
                if (!query.log_sources || !query.log_sources.some(source => source.toLowerCase() === this.currentFilters.logSource.toLowerCase())) {
                    return false;
                }
            }

            // CS Required Modules filter
            if (this.currentFilters.csRequiredModules && this.currentFilters.csRequiredModules.length > 0) {
                if (!query.cs_required_modules || !Array.isArray(query.cs_required_modules)) {
                    return false;
                }
                
                // Check if query has ONLY modules from the selected set (no additional modules)
                const queryModulesLower = query.cs_required_modules.map(module => module.toLowerCase());
                const selectedModulesLower = this.currentFilters.csRequiredModules.map(module => module.toLowerCase());
                
                // Query modules must be a subset of selected modules
                const hasOnlySelectedModules = queryModulesLower.every(queryModule => 
                    selectedModulesLower.includes(queryModule)
                );
                
                if (!hasOnlySelectedModules) {
                    return false;
                }
            }

            return true;
        });

        // Reset to first page when filters change
        this.currentPage = 1;

        // Apply sorting to filtered results
        this.applySorting();

        // Update filter options based on current filtered results
        this.populateFilters();

        this.displayQueries();
    }

    applySorting() {
        // Sort filteredQueries by created_date
        this.filteredQueries.sort((a, b) => {
            const dateA = a.created_date ? new Date(a.created_date).getTime() : 0;
            const dateB = b.created_date ? new Date(b.created_date).getTime() : 0;

            if (this.currentSort === 'asc') {
                // Ascending: oldest first
                // Queries without dates go to the end
                if (dateA === 0) return 1;
                if (dateB === 0) return -1;
                return dateA - dateB;
            } else {
                // Descending: newest first (default)
                // Queries without dates go to the end
                if (dateA === 0) return 1;
                if (dateB === 0) return -1;
                return dateB - dateA;
            }
        });
    }

    displayQueries() {
        const resultsContainer = document.getElementById('queryResults');
        const resultsCount = document.getElementById('resultsCount');
        if (!resultsContainer || !resultsCount) return;

        if (this.isLoadingQueries && this.filteredQueries.length === 0) {
            resultsCount.textContent = 'Loading queries...';
            resultsContainer.innerHTML = this.renderLoadingSkeletons(6, 'query');
            this.hidePagination();
            return;
        }

        resultsCount.textContent = `${this.filteredQueries.length} queries found`;

        if (this.filteredQueries.length === 0) {
            resultsContainer.innerHTML = `
                <div class="no-results">
                    <h3>No queries found</h3>
                    <p>Try adjusting your search terms or filters.</p>
                </div>
            `;
            this.hidePagination();
            return;
        }

        // Handle pagination
        this.updatePagination();
        
        // Get queries for current page
        const startIndex = (this.currentPage - 1) * this.queriesPerPage;
        const endIndex = this.queriesPerPage === 'all' ? this.filteredQueries.length : startIndex + this.queriesPerPage;
        this.displayedQueries = this.filteredQueries.slice(startIndex, endIndex);

        resultsContainer.innerHTML = this.displayedQueries.map(query => this.createQueryCard(query)).join('');
        
        // Bind copy button events
        this.bindCopyEvents();
        // Bind falcon button events
        this.bindFalconEvents();
        // Bind query card click events
        this.bindQueryCardEvents();
        // Update falcon button states
        this.updateFalconButtonsState();
        
        // Show pagination if needed
        this.showPaginationIfNeeded();
    }

    createQueryCard(query) {
        const tags = query.tags ? query.tags.map(tag => `<span class="tag">${this.escapeHtml(tag)}</span>`).join('') : '';
        const logSources = query.log_sources ? query.log_sources.map(source => `<span class="tag">${this.escapeHtml(source)}</span>`).join('') : '';
        const requiredModules = query.cs_required_modules ? query.cs_required_modules.map(module => `<span class="tag">${this.escapeHtml(module)}</span>`).join('') : '';
        const mitreIds = query.mitre_ids ? query.mitre_ids.map(id => `<span class="mitre-id">${this.escapeHtml(id)}</span>`).join('') : '';

        return `
            <div class="query-card">
                <div class="query-header">
                    <div class="query-title">${this.escapeHtml(query.name)}</div>
                    ${mitreIds ? `<div class="mitre-ids">${mitreIds}</div>` : ''}
                </div>

                <div class="query-description">
                    ${this.escapeHtml(query.description)}
                </div>

                <div class="query-tags">
                ${tags ? `<div class="tags"><span class="section-label"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-tag text-cql-blue" aria-hidden="true"><path d="M12.586 2.586A2 2 0 0 0 11.172 2H4a2 2 0 0 0-2 2v7.172a2 2 0 0 0 .586 1.414l8.704 8.704a2.426 2.426 0 0 0 3.42 0l6.58-6.58a2.426 2.426 0 0 0 0-3.42z"></path><circle cx="7.5" cy="7.5" r=".5" fill="currentColor"></circle></svg></span> ${tags}</div>` : ''}
                ${logSources ? `<div class="tags"><span class="section-label"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-database text-cql-highlight" aria-hidden="true"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M3 5V19A9 3 0 0 0 21 19V5"></path><path d="M3 12A9 3 0 0 0 21 12"></path></svg></span> ${logSources}</div>` : ''}
                ${requiredModules ? `<div class="tags"><span class="section-label"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-box text-cql-red" aria-hidden="true"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"></path><path d="m3.3 7 8.7 5 8.7-5"></path><path d="M12 22V12"></path></svg></span> ${requiredModules}</div>` : ''}
                ${query.created_date ? `<div class="tags">
                        <span class="section-label">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-box text-cql-red" aria-hidden="true"><path d="M3.5 0a.5.5 0 0 1 .5.5V1h8V.5a.5.5 0 0 1 1 0V1h1a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V3a2 2 0 0 1 2-2h1V.5a.5.5 0 0 1 .5-.5M1 4v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V4z"/></svg></span>
                        <span class="tag">${this.formatDate(query.created_date)}</span></div>` : ''}
                </div>
                <div class="query-code-box">
                    <div class="query-code-gradient"></div>
                    <div class="query-code">${this.escapeHtml(query.cql)}</div>
                </div>
                <div class="query-meta">
                    <div class="meta-row">
                        <span class="meta-label">Author:</span>
                        <span class="meta-value">${this.escapeHtml(query.author)}</span>
                    </div>
                    <div class="query-actions">
                    <button class="copy-button" data-query-name="${this.escapeHtml(query.name)}">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-copy" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>
                    </button>
                    <button class="falcon-button" data-query-name="${this.escapeHtml(query.name)}">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="bi bi-search" viewBox="0 0 16 16"><path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"></path></svg>
                        <span>Run</span>

                    </button>
                </div>
                </div>

            </div>
        `;
    }

    bindCopyEvents() {
        const copyButtons = document.querySelectorAll('.copy-button');
        copyButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const queryName = e.target.getAttribute('data-query-name');
                const query = this.queries.find(q => q.name === queryName);
                if (query) {
                    this.copyToClipboard(query.cql, e.target);
                }
            });
        });
    }

    bindFalconEvents() {
        const falconButtons = document.querySelectorAll('.falcon-button');
        falconButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                if (button.disabled) return;
                
                const queryName = e.target.getAttribute('data-query-name');
                const query = this.queries.find(q => q.name === queryName);
                
                if (query && this.selectedFalconRegion) {
                    const falconUrl = this.generateFalconUrl(query.cql, this.selectedFalconRegion);
                    window.open(falconUrl, '_blank');
                }
            });
        });
    }

    updateFalconButtonsState() {
        const falconButtons = document.querySelectorAll('.falcon-button');
        const hasRegion = this.selectedFalconRegion !== '';
        
        falconButtons.forEach(button => {
            button.disabled = !hasRegion;
            if (hasRegion) {
                button.classList.remove('disabled');
                button.removeAttribute('data-tooltip');
            } else {
                button.classList.add('disabled');
                button.setAttribute('data-tooltip', 'Please set your Falcon Region first');
            }
        });

        // Also update modal button if it exists
        this.updateModalButtonStates();
    }

    async copyToClipboard(text, button) {
        try {
            await navigator.clipboard.writeText(text);
            const originalText = button.textContent;
            button.textContent = 'Copied!';
            button.classList.add('copied');
            
            setTimeout(() => {
                button.textContent = originalText;
                button.classList.remove('copied');
            }, 2000);
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            
            button.textContent = 'Copied!';
            setTimeout(() => {
                button.textContent = 'Copy Query';
            }, 2000);
        }
    }

    clearAllFilters() {
        this.currentFilters = {
            search: '',
            tag: '',
            mitreId: '',
            logSource: '',
            csRequiredModules: []
        };

        document.getElementById('searchInput').value = '';
        
        // Clear custom select dropdowns
        this.clearCustomSelect('tagFilter', 'All Tags');
        this.clearCustomSelect('mitreIdFilter', 'All MITRE IDs');
        this.clearCustomSelect('logSourceFilter', 'All Log Sources');
        
        // Clear custom multi-select dropdown
        const csRequiredModulesDropdown = document.getElementById('csRequiredModulesDropdown');
        if (csRequiredModulesDropdown) {
            const checkboxes = csRequiredModulesDropdown.querySelectorAll('input[type="checkbox"]');
            checkboxes.forEach(checkbox => {
                checkbox.checked = false;
            });
            this.updateMultiSelectButtonText();
            this.closeMultiSelectDropdown();
        }

        // Reset pagination to first page
        this.currentPage = 1;
        
        // Repopulate filters based on all queries since we cleared filters
        this.populateFiltersFromAllQueries();
        
        this.filterQueries();
    }

    displayError(message) {
        const resultsContainer = document.getElementById('queryResults');
        const resultsCount = document.getElementById('resultsCount');
        
        resultsCount.textContent = 'Error loading queries';
        resultsContainer.innerHTML = `
            <div class="no-results">
                <h3>Error</h3>
                <p>${this.escapeHtml(message)}</p>
            </div>
        `;
    }

    generateFalconUrl(query, region) {
        const baseUrl = this.falconUrls[region];
        const encodedQuery = encodeURIComponent(query);
        return baseUrl + encodedQuery;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    stripExtension(filename) {
        return filename.replace(/\.[^.]+$/, '');
    }

    showToast(message, type = 'success', duration = 4000) {
        const existing = document.querySelector('.toast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        document.body.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'toastFadeOut 0.3s ease-out forwards';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }

    formatDate(dateString) {
        if (!dateString) return '';

        try {
            const date = new Date(dateString);
            // Format as "Month DD, YYYY"
            const options = { year: 'numeric', month: 'short', day: 'numeric' };
            return date.toLocaleDateString('en-US', options);
        } catch (error) {
            console.error('Error formatting date:', error);
            return dateString; // Return original string if parsing fails
        }
    }

    unescapeQuotes(obj) {
        // Recursively process all string properties to unescape quotes
        if (typeof obj === 'string') {
            return obj;
        } else if (Array.isArray(obj)) {
            return obj.map(item => this.unescapeQuotes(item));
        } else if (obj && typeof obj === 'object') {
            Object.keys(obj).forEach(key => {
                obj[key] = this.unescapeQuotes(obj[key]);
            });
        }
        return obj;
    }

    // Cookie helper methods
    setCookie(name, value, days = 30) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        const expires = "expires=" + date.toUTCString();
        document.cookie = name + "=" + value + ";" + expires + ";path=/";
    }

    getCookie(name) {
        const nameEQ = name + "=";
        const ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) == ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
        }
        return null;
    }

    bindModalEvents() {
        const modal = document.getElementById('queryModal');
        const closeBtn = document.querySelector('.close');

        // Close modal when clicking X
        closeBtn.addEventListener('click', () => this.closeModal());

        // Close modal when clicking outside
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.closeModal();
            }
        });

        // Close modal with Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && modal.style.display === 'block') {
                this.closeModal();
            }
        });
    }

    bindModalButtonEvents() {
        const modalCopyBtn = document.getElementById('modalCopyButton');
        const modalFalconBtn = document.getElementById('modalFalconButton');

        if (modalCopyBtn) {
            modalCopyBtn.addEventListener('click', () => {
                if (this.currentQuery) {
                    this.copyToClipboard(this.currentQuery.cql, modalCopyBtn);
                }
            });
        }

        if (modalFalconBtn) {
            modalFalconBtn.addEventListener('click', () => {
                if (this.currentQuery && this.selectedFalconRegion) {
                    const falconUrl = this.generateFalconUrl(this.currentQuery.cql, this.selectedFalconRegion);
                    window.open(falconUrl, '_blank');
                }
            });
        }
    }

    bindQueryCardEvents() {
        const queryCards = document.querySelectorAll('.query-card');
        queryCards.forEach(card => {
            card.addEventListener('click', (e) => {
                // Don't open modal if clicking on buttons
                if (e.target.closest('.query-actions')) {
                    return;
                }
                
                const queryName = card.querySelector('[data-query-name]')?.getAttribute('data-query-name');
                const query = this.queries.find(q => q.name === queryName);
                if (query) {
                    this.openModal(query);
                }
            });
        });
    }

    openModal(query) {
        this.currentQuery = query;
        history.replaceState(null, '', `#queries/${encodeURIComponent(this.stripExtension(query.filename))}`);
        const modal = document.getElementById('queryModal');

        // Populate modal content with inline GitHub link
        const githubUrl = `${this.githubRepoUrl}/blob/main/queries/${encodeURIComponent(query.filename)}`;
        document.getElementById('modalTitle').innerHTML = `${this.escapeHtml(query.name)} <a href="${this.escapeHtml(githubUrl)}" target="_blank" rel="noopener noreferrer"><img src="github-mark-white.svg" alt="View on GitHub" class="github-logo"></a>`;
        
        // Set author in header
        const modalAuthor = document.getElementById('modalAuthor');
        modalAuthor.textContent = `by ${query.author || 'Unknown'}`;
        
        // MITRE IDs
        const modalMitreIds = document.getElementById('modalMitreIds');
        if (query.mitre_ids && query.mitre_ids.length > 0) {
            modalMitreIds.innerHTML = query.mitre_ids.map(id => `<span class="mitre-id">${this.escapeHtml(id)}</span>`).join('');
            modalMitreIds.style.display = 'flex';
        } else {
            modalMitreIds.style.display = 'none';
        }
        
        // Description
        document.getElementById('modalDescription').textContent = query.description;

        // Meta information - show creation date if available
        const modalMeta = document.getElementById('modalMeta');
        if (query.created_date) {
            modalMeta.innerHTML = `
                <div class="meta-row">
                    <span class="meta-label">Created:</span>
                    <span class="meta-value">${this.formatDate(query.created_date)}</span>
                </div>
            `;
            modalMeta.style.display = 'block';
        } else {
            modalMeta.style.display = 'none';
        }
        
        // CQL Code (moved up in order, with buttons in heading)
        const modalCode = document.getElementById('modalCode');
        modalCode.innerHTML = `
            <div class="modal-section-heading-container">
                <h3 class="modal-section-heading">Query</h3>
                <div class="modal-section-buttons">
                    <button id="modalCopyButton" class="copy-button">Copy Query</button>
                    <button id="modalFalconButton" class="falcon-button">Run Query in Falcon</button>
                </div>
            </div>
            <div class="modal-section-content"><pre>${this.escapeHtml(query.cql)}</pre></div>
        `;
        
        // Explanation (render markdown-like content)
        const modalExplanation = document.getElementById('modalExplanation');
        if (query.explanation) {
            modalExplanation.innerHTML = `
                <h3 class="modal-section-heading">Explanation</h3>
                <div class="modal-section-content">${this.renderMarkdown(query.explanation)}</div>
            `;
            modalExplanation.style.display = 'block';
        } else {
            modalExplanation.style.display = 'none';
        }
        
        // Log Sources
        const modalLogSources = document.getElementById('modalLogSources');
        if (query.log_sources && query.log_sources.length > 0) {
            modalLogSources.innerHTML = `
                <h3 class="modal-section-heading">Log Sources</h3>
                <div class="modal-section-content">${query.log_sources.map(source => `<span class="log-source">${this.escapeHtml(source)}</span>`).join('')}</div>
            `;
            modalLogSources.style.display = 'block';
        } else {
            modalLogSources.style.display = 'none';
        }
        
        // Required Modules
        const modalRequiredModules = document.getElementById('modalRequiredModules');
        if (query.cs_required_modules && query.cs_required_modules.length > 0) {
            modalRequiredModules.innerHTML = `
                <h3 class="modal-section-heading">Required Modules</h3>
                <div class="modal-section-content">${query.cs_required_modules.map(module => `<span class="required-module">${this.escapeHtml(module)}</span>`).join('')}</div>
            `;
            modalRequiredModules.style.display = 'block';
        } else {
            modalRequiredModules.style.display = 'none';
        }
        
        // Tags
        const modalTags = document.getElementById('modalTags');
        if (query.tags && query.tags.length > 0) {
            modalTags.innerHTML = `
                <h3 class="modal-section-heading">Tags</h3>
                <div class="modal-section-content">${query.tags.map(tag => `<span class="tag">${this.escapeHtml(tag)}</span>`).join('')}</div>
            `;
            modalTags.style.display = 'block';
        } else {
            modalTags.style.display = 'none';
        }

        // Lookup Files references
        const lookupRefs = this.queryToLookups[query.name] || { cqlHub: [], preSupplied: [], missing: [] };
        const hasLookupRefs = lookupRefs.cqlHub.length > 0 || lookupRefs.preSupplied.length > 0 || lookupRefs.missing.length > 0;
        const modalLookupFiles = document.getElementById('modalLookupFiles');
        if (modalLookupFiles) {
            if (hasLookupRefs) {
                const cqlHubHtml = lookupRefs.cqlHub.map(f => `<span class="lookup-ref cqlhub" data-lookup-name="${this.escapeHtml(f)}">${this.escapeHtml(f)} <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="bi bi-arrow-right" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M1 8a.5.5 0 0 1 .5-.5h11.793l-3.147-3.146a.5.5 0 0 1 .708-.708l4 4a.5.5 0 0 1 0 .708l-4 4a.5.5 0 0 1-.708-.708L13.293 8.5H1.5A.5.5 0 0 1 1 8"/></svg></span>`).join(' ');
                const preSuppliedHtml = lookupRefs.preSupplied.map(f => `<span class="lookup-ref presupplied">${this.escapeHtml(f)} (CrowdStrike-managed)</span>`).join(' ');
                const missingHtml = lookupRefs.missing.map(f => `<span class="lookup-ref missing">${this.escapeHtml(f)} (Missing)</span>`).join(' ');

                modalLookupFiles.innerHTML = `
                    <h3 class="modal-section-heading">Lookup Files</h3>
                    <div class="lookup-refs" style="margin-top: 0.5rem;">
                        ${cqlHubHtml} ${preSuppliedHtml} ${missingHtml}
                    </div>
                `;
                modalLookupFiles.style.display = 'block';

                modalLookupFiles.querySelectorAll('.lookup-ref.cqlhub').forEach(link => {
                    link.addEventListener('click', (e) => {
                        const lookupName = e.target.dataset.lookupName;
                        const file = this.lookupFiles.find(f => f.name === lookupName);
                        if (file) {
                            this.closeModal();
                            this.switchView('lookups');
                            this.openLookupModal(file);
                        }
                    });
                });
            } else {
                modalLookupFiles.style.display = 'none';
            }
        }
        
        // Bind button events (since buttons are dynamically created)
        this.bindModalButtonEvents();
        
        // Update modal button states
        this.updateModalButtonStates();
        
        // Show modal
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden'; // Prevent background scrolling
    }

    closeModal() {
        const modal = document.getElementById('queryModal');
        modal.style.display = 'none';
        document.body.style.overflow = 'auto'; // Restore background scrolling
        this.currentQuery = null;
        history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
    }

    updateModalButtonStates() {
        const modalFalconBtn = document.getElementById('modalFalconButton');
        if (!modalFalconBtn) return; // Button doesn't exist yet, skip update
        
        const hasRegion = this.selectedFalconRegion !== '';
        
        modalFalconBtn.disabled = !hasRegion;
        if (hasRegion) {
            modalFalconBtn.classList.remove('disabled');
            modalFalconBtn.removeAttribute('data-tooltip');
        } else {
            modalFalconBtn.classList.add('disabled');
            modalFalconBtn.setAttribute('data-tooltip', 'Please set your Falcon Region first');
        }
    }

    renderMarkdown(text) {
        if (!text) return '';
        
        // Configure marked.js options
        marked.setOptions({
            breaks: true, // Convert single line breaks to <br>
            gfm: true, // GitHub Flavored Markdown
            sanitize: false, // DOMPurify will handle sanitization
            headerIds: false, // Don't add IDs to headers
            mangle: false // Don't mangle email addresses
        });
        
        // Use marked.js to render the markdown, then sanitize with DOMPurify
        const rawHtml = marked.parse(text);
        return DOMPurify.sanitize(rawHtml);
    }

    // YAML Builder Methods
    openYamlBuilder() {
        const modal = document.getElementById('yamlBuilderModal');
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }

    closeYamlBuilder() {
        const modal = document.getElementById('yamlBuilderModal');
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }

    bindYamlBuilderEvents() {
        const modal = document.getElementById('yamlBuilderModal');
        const closeBtn = document.querySelector('.yaml-builder-close');
        const downloadBtn = document.getElementById('downloadYamlButton');
        const form = document.getElementById('yamlBuilderForm');

        // Close modal when clicking X
        closeBtn.addEventListener('click', () => this.closeYamlBuilder());

        // Close modal when clicking outside
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.closeYamlBuilder();
            }
        });

        // Close modal with Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && modal.style.display === 'block') {
                this.closeYamlBuilder();
            }
        });

        // Download YAML button
        downloadBtn.addEventListener('click', () => this.generateAndDownloadYaml());

        // Submit Query button
        const submitBtn = document.getElementById('submitQueryButton');
        submitBtn.addEventListener('click', () => this.submitQuery());

        // Preview markdown button
        const previewBtn = document.getElementById('previewMarkdownButton');
        previewBtn.addEventListener('click', () => this.toggleMarkdownPreview());

        // Form reset button (handled by default reset behavior)

        // Contribute tab switching
        document.querySelectorAll('.contribute-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.contribute-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');

                const queryTab = document.getElementById('contributeQueryTab');
                const lookupTab = document.getElementById('contributeLookupTab');

                if (tab.dataset.tab === 'query') {
                    queryTab.style.display = '';
                    lookupTab.style.display = 'none';
                } else {
                    queryTab.style.display = 'none';
                    lookupTab.style.display = '';
                }
            });
        });

        // CSV file upload handling
        const csvUploadZone = document.getElementById('csvUploadZone');
        const csvFileInput = document.getElementById('csvFileInput');
        const csvRemoveBtn = document.getElementById('csvRemoveBtn');

        csvUploadZone.addEventListener('click', (e) => {
            if (e.target !== csvRemoveBtn && !csvRemoveBtn.contains(e.target)) {
                csvFileInput.click();
            }
        });

        csvFileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.handleCsvFileSelect(e.target.files[0]);
            }
        });

        csvUploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            csvUploadZone.classList.add('dragover');
        });

        csvUploadZone.addEventListener('dragleave', () => {
            csvUploadZone.classList.remove('dragover');
        });

        csvUploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            csvUploadZone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                this.handleCsvFileSelect(e.dataTransfer.files[0]);
            }
        });

        csvRemoveBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            this.clearCsvFile();
        });

        // Submit Lookup File button
        const submitLookupBtn = document.getElementById('submitLookupButton');
        submitLookupBtn.addEventListener('click', () => this.submitLookupFile());

        // Lookup form reset
        const lookupResetBtn = document.getElementById('lookupResetBtn');
        lookupResetBtn.addEventListener('click', () => {
            this.clearCsvFile();
        });

        // Contact field → privacy checkbox toggle (query tab)
        const queryContact = document.getElementById('yamlContact');
        const queryPrivacy = document.getElementById('queryPrivacyConsent');
        queryContact.addEventListener('input', () => {
            queryPrivacy.style.display = queryContact.value.trim() ? 'block' : 'none';
            if (!queryContact.value.trim()) {
                document.getElementById('queryPrivacyCheckbox').checked = false;
            }
        });

        // Contact field → privacy checkbox toggle (lookup tab)
        const lookupContact = document.getElementById('lookupContact');
        const lookupPrivacy = document.getElementById('lookupPrivacyConsent');
        lookupContact.addEventListener('input', () => {
            lookupPrivacy.style.display = lookupContact.value.trim() ? 'block' : 'none';
            if (!lookupContact.value.trim()) {
                document.getElementById('lookupPrivacyCheckbox').checked = false;
            }
        });
    }

    collectFormData() {
        const form = document.getElementById('yamlBuilderForm');
        const formData = new FormData(form);

        // Validate required fields
        const requiredFields = [
            { key: 'name', elementId: 'yamlName' },
            { key: 'author', elementId: 'yamlAuthor' },
            { key: 'description', elementId: 'yamlDescription' },
            { key: 'cql', elementId: 'yamlCql' }
        ];

        for (const field of requiredFields) {
            if (!formData.get(field.key)?.trim()) {
                this.showToast(`Please fill in the required field: ${field.key.charAt(0).toUpperCase() + field.key.slice(1)}`, 'warning');
                document.getElementById(field.elementId).focus();
                return null;
            }
        }

        // Parse comma-separated fields
        const parseCommaSeparated = (value) => {
            if (!value?.trim()) return [];
            return value.split(',').map(item => item.trim()).filter(item => item);
        };

        // Build the data object
        const data = {
            name: formData.get('name').trim(),
            description: formData.get('description').trim(),
            author: formData.get('author').trim(),
            cql: formData.get('cql').trim()
        };

        // Add optional contact field
        const contact = formData.get('contact')?.trim();
        if (contact) {
            if (!document.getElementById('queryPrivacyCheckbox').checked) {
                this.showToast('Please accept the Privacy Policy to submit your contact information.', 'warning');
                return null;
            }
            data.contact = contact;
        }

        // Add optional fields if they exist
        const explanation = formData.get('explanation')?.trim();
        if (explanation) {
            data.explanation = explanation;
        }

        // Get selected tags from checkboxes
        const tagCheckboxes = form.querySelectorAll('input[name="tags"]:checked');
        const tags = Array.from(tagCheckboxes).map(checkbox => checkbox.value);
        if (tags.length > 0) {
            data.tags = tags;
        }

        // Get selected log sources from checkboxes
        const logSourceCheckboxes = form.querySelectorAll('input[name="log_sources"]:checked');
        const logSources = Array.from(logSourceCheckboxes).map(checkbox => checkbox.value);
        if (logSources.length > 0) {
            data.log_sources = logSources;
        }

        const mitreIds = parseCommaSeparated(formData.get('mitre_ids'));
        if (mitreIds.length > 0) {
            data.mitre_ids = mitreIds;
        }

        // Get selected required modules from checkboxes
        const requiredModuleCheckboxes = form.querySelectorAll('input[name="cs_required_modules"]:checked');
        const requiredModules = Array.from(requiredModuleCheckboxes).map(checkbox => checkbox.value);
        if (requiredModules.length > 0) {
            data.cs_required_modules = requiredModules;
        }

        return data;
    }

    generateAndDownloadYaml() {
        const data = this.collectFormData();
        if (!data) return;

        // Generate YAML string
        const yamlString = this.objectToYaml(data);

        // Create and download file
        const blob = new Blob([yamlString], { type: 'text/yaml' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${data.name.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.yml`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);

        // Show success message
        const downloadBtn = document.getElementById('downloadYamlButton');
        const originalText = downloadBtn.textContent;
        downloadBtn.textContent = 'Downloaded!';
        downloadBtn.style.background = '#059669';

        setTimeout(() => {
            downloadBtn.textContent = originalText;
            downloadBtn.style.background = '';
        }, 2000);
    }

    async submitQuery() {
        const data = this.collectFormData();
        if (!data) return;

        // Check if a query with this name already exists
        const existingQuery = this.queries.find(q => q.name.toLowerCase() === data.name.toLowerCase());
        if (existingQuery) {
            this.showToast(`A query with the name "${data.name}" already exists.`, 'warning', 6000);
            return;
        }

        // Check for custom saved search references (e.g. $InstalledBrowserExtensionNormalized(), $rtr())
        const savedSearchPattern = /\$[A-Za-z0-9_]+\(\)/;
        const savedSearchMatch = data.cql.match(savedSearchPattern);
        if (savedSearchMatch) {
            this.showToast(`Query contains a custom saved search reference "${savedSearchMatch[0]}" which is not allowed. Please use only standard CQL syntax.`, 'warning', 6000);
            return;
        }

        // Check for lookup file references that aren't in CQL Hub or CrowdStrike-managed
        const matchFileRegex = /match\s*\(\s*file\s*=\s*"([^"]+)"/g;
        const cqlHubNames = new Set(this.lookupFiles.map(f => f.name));
        const preSuppliedSet = new Set(this.preSuppliedLookupFiles);
        const missingLookups = [];
        let fileMatch;
        while ((fileMatch = matchFileRegex.exec(data.cql)) !== null) {
            const filename = fileMatch[1];
            if (!cqlHubNames.has(filename) && !preSuppliedSet.has(filename) && !missingLookups.includes(filename)) {
                missingLookups.push(filename);
            }
        }

        const submitBtn = document.getElementById('submitQueryButton');
        const originalText = submitBtn.textContent;

        submitBtn.disabled = true;
        submitBtn.textContent = 'Submitting...';

        try {
            const response = await fetch(`${this.apiBaseUrl}/submissions`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });

            if (response.ok) {
                const responseData = await response.json();
                this.closeYamlBuilder();
                document.getElementById('yamlBuilderForm').reset();
                submitBtn.textContent = originalText;
                submitBtn.style.background = '';
                submitBtn.disabled = false;
                const successMessage = responseData.pull_request_url
                    ? `Query submitted for approval. PR: ${responseData.pull_request_url}`
                    : 'Query submitted for approval.';
                if (missingLookups.length > 0) {
                    const fileList = missingLookups.map(f => `"${f}"`).join(', ');
                    this.showToast(`${successMessage} It references lookup file(s) not yet available: ${fileList}. Please also submit those lookup files for approval.`, 'warning', 9000);
                } else {
                    this.showToast(successMessage, 'success', 9000);
                }
                return;
            }

            if (response.status === 422) {
                const errorData = await response.json();
                const messages = this.formatValidationErrors(errorData);
                this.showToast(`Validation error:\n${messages}`, 'error', 6000);
            } else if (response.status === 503) {
                this.showToast('The submission service is currently unavailable. Please try again later.', 'error', 6000);
            } else if (response.status === 502) {
                this.showToast('There was an error processing your submission. Please try again later.', 'error', 6000);
            } else {
                this.showToast(`Submission failed (Error ${response.status}). Please try again later.`, 'error', 6000);
            }
        } catch (error) {
            console.error('Submission error:', error);
            this.showToast('Failed to submit query. Please check your internet connection and try again.', 'error', 6000);
        }

        submitBtn.textContent = originalText;
        submitBtn.style.background = '';
        submitBtn.disabled = false;
    }

    formatValidationErrors(errorData) {
        if (errorData.detail && Array.isArray(errorData.detail)) {
            return errorData.detail.map(err => {
                const field = err.loc ? err.loc[err.loc.length - 1] : 'unknown';
                return `- ${field}: ${err.msg}`;
            }).join('\n');
        }
        if (errorData.detail && typeof errorData.detail === 'string') {
            return errorData.detail;
        }
        return 'Unknown validation error. Please check your input.';
    }

    handleCsvFileSelect(file) {
        if (!file.name.endsWith('.csv')) {
            this.showToast('Please select a CSV file.', 'warning');
            return;
        }

        const maxSize = 5 * 1024 * 1024; // 5 MB
        if (file.size > maxSize) {
            this.showToast('File size exceeds the 5 MB limit.', 'warning');
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            this.csvFileContent = e.target.result;
            this.csvFileName = file.name;

            // Show file info
            document.getElementById('csvUploadPlaceholder').style.display = 'none';
            const fileInfo = document.getElementById('csvFileInfo');
            fileInfo.style.display = 'flex';
            document.getElementById('csvFileName').textContent = file.name;
            document.getElementById('csvFileSize').textContent = `(${(file.size / 1024).toFixed(1)} KB)`;

            // Generate preview
            this.renderCsvPreview(this.csvFileContent);
        };
        reader.readAsText(file);
    }

    renderCsvPreview(csvText) {
        const lines = csvText.split('\n').filter(line => line.trim());
        if (lines.length === 0) {
            document.getElementById('csvPreviewSection').style.display = 'none';
            return;
        }

        const parseRow = (line) => {
            const result = [];
            let current = '';
            let inQuotes = false;
            for (let i = 0; i < line.length; i++) {
                const ch = line[i];
                if (ch === '"') {
                    inQuotes = !inQuotes;
                } else if (ch === ',' && !inQuotes) {
                    result.push(current.trim());
                    current = '';
                } else {
                    current += ch;
                }
            }
            result.push(current.trim());
            return result;
        };

        const headers = parseRow(lines[0]);
        const previewRows = lines.slice(1, 6).map(line => parseRow(line));

        let html = '<div class="lookup-preview-table-wrapper"><table class="lookup-preview-table"><thead><tr>';
        headers.forEach(h => {
            html += `<th>${this.escapeHtml(h)}</th>`;
        });
        html += '</tr></thead><tbody>';
        previewRows.forEach(row => {
            html += '<tr>';
            headers.forEach((_, i) => {
                html += `<td>${this.escapeHtml(row[i] || '')}</td>`;
            });
            html += '</tr>';
        });
        html += '</tbody></table></div>';

        const totalRows = lines.length - 1;
        const remaining = totalRows - previewRows.length;
        if (remaining > 0) {
            html += `<p class="lookup-preview-more">and ${remaining.toLocaleString()} more entries</p>`;
        }

        document.getElementById('csvPreviewContainer').innerHTML = html;
        document.getElementById('csvPreviewSection').style.display = '';
    }

    clearCsvFile() {
        this.csvFileContent = null;
        this.csvFileName = null;
        document.getElementById('csvFileInput').value = '';
        document.getElementById('csvUploadPlaceholder').style.display = '';
        document.getElementById('csvFileInfo').style.display = 'none';
        document.getElementById('csvPreviewSection').style.display = 'none';
        document.getElementById('csvPreviewContainer').innerHTML = '';
    }

    async submitLookupFile() {
        const description = document.getElementById('lookupDescription').value.trim();
        const author = document.getElementById('lookupAuthor').value.trim();
        const contact = document.getElementById('lookupContact').value.trim();

        if (!this.csvFileContent || !this.csvFileName) {
            this.showToast('Please upload a CSV file.', 'warning');
            return;
        }

        if (!description || !author) {
            this.showToast('Please fill in all required fields.', 'warning');
            return;
        }

        if (contact && !document.getElementById('lookupPrivacyCheckbox').checked) {
            this.showToast('Please accept the Privacy Policy to submit your contact information.', 'warning');
            return;
        }

        const filename = this.csvFileName;

        // Check if a lookup file with this filename already exists
        const existingFile = this.lookupFiles.find(f => f.name.toLowerCase() === filename.toLowerCase());
        if (existingFile) {
            this.showToast(`A lookup file with the filename "${filename}" already exists.`, 'warning', 6000);
            return;
        }

        const submitBtn = document.getElementById('submitLookupButton');
        const originalText = submitBtn.textContent;

        submitBtn.disabled = true;
        submitBtn.textContent = 'Submitting...';

        try {
            const response = await fetch(`${this.apiBaseUrl}/lookup-submissions`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    filename,
                    description,
                    author,
                    csv_content: this.csvFileContent,
                    ...(contact && { contact })
                })
            });

            if (response.ok) {
                const responseData = await response.json();
                this.closeYamlBuilder();
                this.clearCsvFile();
                document.getElementById('lookupBuilderForm').reset();
                submitBtn.textContent = originalText;
                submitBtn.style.background = '';
                submitBtn.disabled = false;
                const successMessage = responseData.pull_request_url
                    ? `Lookup file submitted for approval. PR: ${responseData.pull_request_url}`
                    : 'Lookup file submitted for approval.';
                this.showToast(successMessage, 'success', 9000);
                return;
            }

            if (response.status === 422) {
                const errorData = await response.json();
                const messages = this.formatValidationErrors(errorData);
                this.showToast(`Validation error:\n${messages}`, 'error', 6000);
            } else if (response.status === 503) {
                this.showToast('The submission service is currently unavailable. Please try again later.', 'error', 6000);
            } else if (response.status === 502) {
                this.showToast('There was an error processing your submission. Please try again later.', 'error', 6000);
            } else {
                this.showToast(`Submission failed (Error ${response.status}). Please try again later.`, 'error', 6000);
            }
        } catch (error) {
            console.error('Lookup submission error:', error);
            this.showToast('Failed to submit lookup file. Please check your internet connection and try again.', 'error', 6000);
        }

        submitBtn.textContent = originalText;
        submitBtn.style.background = '';
        submitBtn.disabled = false;
    }

    objectToYaml(obj) {
        let yaml = '';
        
        // Add header comment
        yaml += '# --- Query Metadata ---\n';
        
        // Name with comment
        yaml += '# Human-readable name for the query. Will be displayed as the title.\n';
        yaml += `name: ${this.escapeYamlValue(obj.name)}\n\n`;
        
        // MITRE IDs with comment
        if (obj.mitre_ids && obj.mitre_ids.length > 0) {
            yaml += '# MITRE ATT&CK technique IDs\n';
            yaml += 'mitre_ids:\n';
            for (const id of obj.mitre_ids) {
                yaml += `  - ${this.escapeYamlValue(id)}\n`;
            }
            yaml += '\n';
        }
        
        // Description with comment
        yaml += '# Description of what the query does and its purpose.\n';
        yaml += '# Using the YAML block scalar `|` allows for multi-line strings.\n';
        yaml += 'description: |\n';
        const descriptionLines = obj.description.split('\n');
        for (const line of descriptionLines) {
            yaml += `  ${line}\n`;
        }
        yaml += '\n';
        
        // Author with comment
        yaml += '# The author or team that created the query.\n';
        yaml += `author: ${this.escapeYamlValue(obj.author)}\n\n`;
        
        // Log sources with comment
        if (obj.log_sources && obj.log_sources.length > 0) {
            yaml += '# The required log sources to run this query successfully in Next-Gen SIEM.\n';
            yaml += '# This will be displayed in the UI to inform the user.\n';
            yaml += 'log_sources:\n';
            for (const source of obj.log_sources) {
                yaml += `  - ${this.escapeYamlValue(source)}\n`;
            }
            yaml += '\n';
        }
        
        // Required modules with comment
        if (obj.cs_required_modules && obj.cs_required_modules.length > 0) {
            yaml += '# The CrowdStrike modules required to run this query.\n';
            yaml += 'cs_required_modules:\n';
            for (const module of obj.cs_required_modules) {
                yaml += `  - ${this.escapeYamlValue(module)}\n`;
            }
            yaml += '\n';
        }
        
        // Tags with comment
        if (obj.tags && obj.tags.length > 0) {
            yaml += '# Tags for filtering and categorization.\n';
            yaml += '# Include relevant techniques, tactics, or platforms.\n';
            yaml += 'tags:\n';
            for (const tag of obj.tags) {
                yaml += `  - ${this.escapeYamlValue(tag)}\n`;
            }
            yaml += '\n';
        }
        
        // Query content section
        yaml += '# --- Query Content ---\n';
        yaml += '# The actual CrowdStrike Query Language (CQL) code.\n';
        yaml += '# Using the YAML block scalar `|` allows for multi-line strings.\n';
        yaml += 'cql: |\n';
        const cqlLines = obj.cql.split('\n');
        for (const line of cqlLines) {
            yaml += `  ${line}\n`;
        }
        yaml += '\n';
        
        // Explanation with comment (if provided)
        if (obj.explanation && obj.explanation.trim()) {
            yaml += '# Explanation of the query.\n';
            yaml += '# Using the YAML block scalar `|` allows for multi-line strings.\n';
            yaml += '# Uses markdown for formatting on the webpage.\n';
            yaml += 'explanation: |\n';
            const explanationLines = obj.explanation.split('\n');
            for (const line of explanationLines) {
                yaml += `  ${line}\n`;
            }
        }
        
        return yaml;
    }

    escapeYamlValue(value) {
        // Escape YAML special characters and quote if necessary
        if (typeof value !== 'string') return value;
        
        // Check if the value needs quoting
        const needsQuotes = /[:#@`|>*&!%{}\[\],?]|^\s|^-|\s$|^(true|false|null|yes|no|on|off)$/i.test(value);
        
        if (needsQuotes) {
            // Escape double quotes and wrap in double quotes
            return `"${value.replace(/"/g, '\\"')}"`;
        }
        
        return value;
    }

    toggleMarkdownPreview() {
        const textarea = document.getElementById('yamlExplanation');
        const previewDiv = document.getElementById('markdownPreview');
        const previewBtn = document.getElementById('previewMarkdownButton');
        
        if (previewDiv.style.display === 'none') {
            // Show preview
            const markdownText = textarea.value.trim();
            
            if (!markdownText) {
                previewDiv.innerHTML = '<p style="color: #94a3b8; font-style: italic;">No explanation text to preview</p>';
            } else {
                // Use the existing renderMarkdown method
                previewDiv.innerHTML = this.renderMarkdown(markdownText);
            }
            
            previewDiv.style.display = 'block';
            textarea.style.display = 'none';
            previewBtn.textContent = 'Edit Markdown';
            previewBtn.classList.add('active');
        } else {
            // Show textarea
            previewDiv.style.display = 'none';
            textarea.style.display = 'block';
            previewBtn.textContent = 'Preview Markdown';
            previewBtn.classList.remove('active');
            textarea.focus();
        }
    }

    // Navigation Methods
    initNavigation() {
        const tabs = document.querySelectorAll('.nav-tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const view = tab.dataset.view;
                history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
                this.switchView(view);
            });
        });

        window.addEventListener('hashchange', () => {
            this.handleHashChange();
        });

        // Store initial hash for processing after data loads
        this.pendingDeepLink = window.location.hash.replace('#', '') || null;

        // Handle view switching immediately
        if (this.pendingDeepLink === 'lookups' || this.pendingDeepLink?.startsWith('lookups/')) {
            this.switchView('lookups');
        }
    }

    switchView(viewName) {
        this.currentView = viewName;

        // Update tab active states
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.view === viewName);
        });

        // Show/hide view sections
        document.getElementById('queriesView').classList.toggle('active', viewName === 'queries');
        document.getElementById('lookupsView').classList.toggle('active', viewName === 'lookups');
    }

    handleHashChange() {
        const hash = window.location.hash.replace('#', '');

        if (hash === '') {
            this.closeModal();
            this.closeLookupModal();
            this.switchView('queries');
        } else if (hash.startsWith('queries/')) {
            const slug = decodeURIComponent(hash.substring('queries/'.length));
            this.switchView('queries');
            const query = this.queries.find(q => this.stripExtension(q.filename) === slug);
            if (query) {
                this.openModal(query);
            }
        } else if (hash.startsWith('lookups/')) {
            const slug = decodeURIComponent(hash.substring('lookups/'.length));
            this.switchView('lookups');
            const file = this.lookupFiles.find(f => this.stripExtension(f.name) === slug);
            if (file) {
                this.openLookupModal(file);
            }
        }
    }

    resolveDeepLink() {
        if (!this.pendingDeepLink) return;

        const hash = this.pendingDeepLink;

        if (hash.startsWith('queries/')) {
            const slug = decodeURIComponent(hash.substring('queries/'.length));
            const query = this.queries.find(q => this.stripExtension(q.filename) === slug);
            if (query) {
                this.openModal(query);
                this.pendingDeepLink = null;
            }
        } else if (hash.startsWith('lookups/')) {
            const slug = decodeURIComponent(hash.substring('lookups/'.length));
            const file = this.lookupFiles.find(f => this.stripExtension(f.name) === slug);
            if (file) {
                this.openLookupModal(file);
                this.pendingDeepLink = null;
            }
        }
    }

    // Lookup Files Methods
    async loadLookupFiles() {
        this.isLoadingLookupFiles = true;
        this.displayLookupFiles();
        try {
            const response = await fetch(`${this.apiBaseUrl}/lookup-files`);
            if (!response.ok) {
                throw new Error(`Lookup request failed with status ${response.status}`);
            }
            const data = await response.json();
            this.lookupFiles = (Array.isArray(data) ? data : []).map(file => ({
                ...file,
                preview: Array.isArray(file.preview) ? file.preview : (Array.isArray(file.preview_rows) ? file.preview_rows : []),
                url: file.url || `${this.githubRawBaseUrl}/main/lookup-files/${encodeURIComponent(file.name)}`
            }));
            this.filteredLookupFiles = [...this.lookupFiles];
            this.isUsingCachedLookupFiles = false;
            this.writeJsonStorage(this.lookupFilesStorageKey, this.lookupFiles);
            this.buildCrossReferences();
            this.displayLookupFiles();
            this.resolveDeepLink();
        } catch (error) {
            console.error('Error loading lookup files:', error);
            if (this.lookupFiles.length > 0) {
                this.filteredLookupFiles = [...this.lookupFiles];
                this.isUsingCachedLookupFiles = true;
                this.buildCrossReferences();
                this.displayLookupFiles();
                return;
            }

            const cachedLookupFiles = this.readJsonStorage(this.lookupFilesStorageKey, []);
            if (Array.isArray(cachedLookupFiles) && cachedLookupFiles.length > 0) {
                this.lookupFiles = cachedLookupFiles;
                this.filteredLookupFiles = [...cachedLookupFiles];
                this.isUsingCachedLookupFiles = true;
                this.buildCrossReferences();
                this.displayLookupFiles();
                return;
            }

            this.lookupFiles = [];
            this.filteredLookupFiles = [];
            this.displayLookupFiles();
        } finally {
            this.isLoadingLookupFiles = false;
            this.displayLookupFiles();
            this.updateCachedDataBanner();
        }
    }

    handleLookupSearch() {
        const searchInput = document.getElementById('lookupSearchInput');
        this.lookupFilters.search = searchInput.value;
        this.filterLookupFiles();
    }

    debounceLookupFilter() {
        clearTimeout(this.lookupFilterTimeout);
        this.lookupFilterTimeout = setTimeout(() => this.filterLookupFiles(), 300);
    }

    filterLookupFiles() {
        this.filteredLookupFiles = this.lookupFiles.filter(file => {
            if (this.lookupFilters.search) {
                const searchLower = this.lookupFilters.search.toLowerCase();
                const searchableText = [
                    file.name,
                    file.description,
                    ...(file.columns || [])
                ].join(' ').toLowerCase();

                if (!searchableText.includes(searchLower)) {
                    return false;
                }
            }
            return true;
        });

        this.lookupCurrentPage = 1;
        this.displayLookupFiles();
    }

    clearLookupFilters() {
        this.lookupFilters = { search: '' };
        document.getElementById('lookupSearchInput').value = '';
        this.lookupCurrentPage = 1;
        this.filteredLookupFiles = [...this.lookupFiles];
        this.displayLookupFiles();
    }

    displayLookupFiles() {
        const resultsContainer = document.getElementById('lookupResults');
        const resultsCount = document.getElementById('lookupResultsCount');

        if (!resultsContainer || !resultsCount) return;

        if (this.isLoadingLookupFiles && this.filteredLookupFiles.length === 0) {
            resultsCount.textContent = 'Loading lookup files...';
            resultsContainer.innerHTML = this.renderLoadingSkeletons(6, 'lookup');
            this.hideLookupPagination();
            return;
        }

        resultsCount.textContent = `${this.filteredLookupFiles.length} lookup file${this.filteredLookupFiles.length !== 1 ? 's' : ''} found`;

        if (this.filteredLookupFiles.length === 0) {
            resultsContainer.innerHTML = `
                <div class="no-results">
                    <h3>No lookup files found</h3>
                    <p>Try adjusting your search terms.</p>
                </div>
            `;
            this.hideLookupPagination();
            return;
        }

        // Handle pagination
        this.updateLookupPagination();

        // Get files for current page
        const startIndex = (this.lookupCurrentPage - 1) * this.lookupPerPage;
        const endIndex = this.lookupPerPage === 'all' ? this.filteredLookupFiles.length : startIndex + this.lookupPerPage;
        this.displayedLookupFiles = this.filteredLookupFiles.slice(startIndex, endIndex);

        resultsContainer.innerHTML = this.displayedLookupFiles.map(file => this.createLookupCard(file)).join('');

        // Bind events
        this.bindLookupCardEvents();
        this.showLookupPaginationIfNeeded();
    }

    createLookupCard(file) {
        const columns = file.columns || [];
        const rowCount = file.row_count || 0;
        const referencingQueries = this.lookupToQueries[file.name] || [];

        // Columns display
        let columnsHtml = '';
        if (columns.length > 0) {
            const columnTags = columns.map(col => `<span class="lookup-column-tag">${this.escapeHtml(col)}</span>`).join('');
            columnsHtml = `
                <div class="lookup-columns">
                    <div class="lookup-columns-label">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v18"></path><rect width="18" height="18" x="3" y="3" rx="2"></rect><path d="M3 9h18"></path><path d="M3 15h18"></path></svg>
                        Columns
                    </div>
                    <div class="lookup-columns-list">${columnTags}</div>
                </div>
            `;
        } else {
            columnsHtml = `<div class="lookup-columns"><span style="color: #94a3b8; font-size: 0.85rem;">Column info unavailable</span></div>`;
        }

        // Stats display
        let statsHtml = '';
        if (columns.length > 0 || rowCount > 0) {
            statsHtml = `
                <div class="lookup-stats">
                    <div class="lookup-stat">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 3h18"></path><path d="M3 9h18"></path><path d="M3 15h18"></path><path d="M3 21h18"></path></svg>
                        <span class="lookup-stat-value">${rowCount.toLocaleString()}</span> entries
                    </div>
                    <div class="lookup-stat">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v18"></path><rect width="18" height="18" x="3" y="3" rx="2"></rect></svg>
                        <span class="lookup-stat-value">${columns.length}</span> columns
                    </div>
                </div>
            `;
        }

        // References display
        let referencesHtml = '';
        if (referencingQueries.length > 0) {
            referencesHtml = `
                <div class="lookup-references">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 9 5 12 1.774-5.226L21 14 9 9z"></path><path d="m16.071 16.071 4.243 4.243"></path><path d="m7.188 2.239.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656-2.12 2.122"></path></svg>
                    Used by <span class="lookup-stat-value">${referencingQueries.length}</span> quer${referencingQueries.length === 1 ? 'y' : 'ies'}
                </div>
            `;
        }

        return `
            <div class="query-card lookup-card" data-lookup-name="${this.escapeHtml(file.name)}">
                <div class="query-header">
                    <div class="query-title">${this.escapeHtml(file.name)}</div>
                </div>

                <div class="query-description">
                    ${this.escapeHtml(file.description)}
                </div>

                ${columnsHtml}
                ${statsHtml}
                ${referencesHtml}

                <div class="query-meta">
                    <div class="meta-row"></div>
                    <div class="query-actions">
                        <a href="${this.escapeHtml(file.url)}" download class="download-btn" onclick="event.stopPropagation();">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" x2="12" y1="15" y2="3"></line></svg>
                            Download
                        </a>
                    </div>
                </div>
            </div>
        `;
    }

    bindLookupCardEvents() {
        const lookupCards = document.querySelectorAll('.lookup-card');
        lookupCards.forEach(card => {
            card.addEventListener('click', (e) => {
                if (e.target.closest('.download-btn')) return;
                const lookupName = card.dataset.lookupName;
                const file = this.lookupFiles.find(f => f.name === lookupName);
                if (file) {
                    this.openLookupModal(file);
                }
            });
        });
    }

    // Lookup Modal Methods
    bindLookupModalEvents() {
        const modal = document.getElementById('lookupModal');
        const closeBtn = document.querySelector('.lookup-modal-close');

        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.closeLookupModal());
        }

        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    this.closeLookupModal();
                }
            });

            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && modal.style.display === 'block') {
                    this.closeLookupModal();
                }
            });
        }
    }

    openLookupModal(file) {
        history.replaceState(null, '', `#lookups/${encodeURIComponent(this.stripExtension(file.name))}`);
        const modal = document.getElementById('lookupModal');
        const columns = file.columns || [];
        const rowCount = file.row_count || 0;
        const preview = file.preview || [];
        const referencingQueries = this.lookupToQueries[file.name] || [];

        // Populate title with inline GitHub link
        const lookupGithubUrl = `${this.githubRepoUrl}/blob/main/lookup-files/${encodeURIComponent(file.name)}`;
        document.getElementById('lookupModalTitle').innerHTML = `${this.escapeHtml(file.name)} <a href="${this.escapeHtml(lookupGithubUrl)}" target="_blank" rel="noopener noreferrer"><img src="github-mark-white.svg" alt="View on GitHub" class="github-logo"></a>`;

        document.getElementById('lookupModalDescription').textContent = file.description;

        // Columns + inline stats
        const columnsEl = document.getElementById('lookupModalColumns');
        const statsEl = document.getElementById('lookupModalStats');
        statsEl.style.display = 'none';

        if (columns.length > 0) {
            columnsEl.innerHTML = `
                <h3 class="modal-section-heading">Columns</h3>
                <div class="modal-section-content">
                    <div class="lookup-columns-list">
                        ${columns.map(col => `<span class="lookup-column-tag">${this.escapeHtml(col)}</span>`).join('')}
                    </div>
                </div>
            `;
            columnsEl.style.display = 'block';
        } else {
            columnsEl.style.display = 'none';
        }

        // Referenced by queries
        const referencedByEl = document.getElementById('lookupModalReferencedBy');
        if (referencingQueries.length > 0) {
            referencedByEl.innerHTML = `
                <h3 class="modal-section-heading">Used by Queries</h3>
                <div class="modal-section-content">
                    ${referencingQueries.map(q => `<button class="lookup-reference-link" data-query-name="${this.escapeHtml(q.name)}">${this.escapeHtml(q.name)}</button>`).join('<br>')}
                </div>
            `;
            referencedByEl.style.display = 'block';

            // Bind query reference clicks
            referencedByEl.querySelectorAll('.lookup-reference-link').forEach(link => {
                link.addEventListener('click', (e) => {
                    const queryName = e.target.dataset.queryName;
                    const query = this.queries.find(q => q.name === queryName);
                    if (query) {
                        this.closeLookupModal();
                        this.switchView('queries');
                        this.openModal(query);
                    }
                });
            });
        } else {
            referencedByEl.style.display = 'none';
        }

        // CSV Preview
        const previewEl = document.getElementById('lookupModalPreview');
        if (preview.length > 0 && columns.length > 0) {
            let tableHtml = '<h3 class="modal-section-heading">Preview (first ' + preview.length + ' rows)</h3>';
            tableHtml += '<div class="modal-section-content" style="overflow-x: auto;"><table class="lookup-preview-table"><thead><tr>';
            columns.forEach(h => { tableHtml += `<th>${this.escapeHtml(h)}</th>`; });
            tableHtml += '</tr></thead><tbody>';
            preview.forEach(row => {
                tableHtml += '<tr>';
                row.forEach(cell => { tableHtml += `<td>${this.escapeHtml(cell)}</td>`; });
                tableHtml += '</tr>';
            });
            tableHtml += '</tbody></table>';
            const remainingEntries = rowCount - preview.length;
            if (remainingEntries > 0) {
                tableHtml += `<p class="lookup-preview-more">and ${remainingEntries.toLocaleString()} more entries</p>`;
            }
            tableHtml += '</div>';
            previewEl.innerHTML = tableHtml;
            previewEl.style.display = 'block';
        } else {
            previewEl.style.display = 'none';
        }

        // Actions
        const actionsEl = document.getElementById('lookupModalActions');
        actionsEl.innerHTML = `
            <a href="${this.escapeHtml(file.url)}" download class="download-btn" style="font-size: 1rem; padding: 0.7rem 1.5rem;">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" x2="12" y1="15" y2="3"></line></svg>
                Download CSV
            </a>
        `;

        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }

    closeLookupModal() {
        const modal = document.getElementById('lookupModal');
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
        history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
    }

    renderLoadingSkeletons(count, type) {
        return Array.from({ length: count }, () => `
            <div class="query-card loading-card loading-card-${type}" aria-hidden="true">
                <div class="loading-line loading-line-title"></div>
                <div class="loading-line loading-line-body"></div>
                <div class="loading-line loading-line-body short"></div>
                <div class="loading-line loading-line-meta"></div>
            </div>
        `).join('');
    }

    updateCachedDataBanner() {
        document.getElementById('cachedDataBanner')?.remove();
    }

    // Lookup Pagination Methods
    bindLookupPaginationEvents() {
        const firstPageBtn = document.getElementById('lookupFirstPageBtn');
        const prevPageBtn = document.getElementById('lookupPrevPageBtn');
        const nextPageBtn = document.getElementById('lookupNextPageBtn');
        const lastPageBtn = document.getElementById('lookupLastPageBtn');

        if (firstPageBtn) {
            firstPageBtn.addEventListener('click', () => {
                this.lookupCurrentPage = 1;
                this.displayLookupFiles();
            });
        }
        if (prevPageBtn) {
            prevPageBtn.addEventListener('click', () => {
                if (this.lookupCurrentPage > 1) {
                    this.lookupCurrentPage--;
                    this.displayLookupFiles();
                }
            });
        }
        if (nextPageBtn) {
            nextPageBtn.addEventListener('click', () => {
                const totalPages = this.getLookupTotalPages();
                if (this.lookupCurrentPage < totalPages) {
                    this.lookupCurrentPage++;
                    this.displayLookupFiles();
                }
            });
        }
        if (lastPageBtn) {
            lastPageBtn.addEventListener('click', () => {
                this.lookupCurrentPage = this.getLookupTotalPages();
                this.displayLookupFiles();
            });
        }
    }

    getLookupTotalPages() {
        if (this.lookupPerPage === 'all') return 1;
        return Math.ceil(this.filteredLookupFiles.length / this.lookupPerPage);
    }

    updateLookupPagination() {
        if (this.lookupPerPage === 'all') return;

        const totalPages = this.getLookupTotalPages();
        const paginationInfo = document.getElementById('lookupPaginationInfo');
        const startIndex = (this.lookupCurrentPage - 1) * this.lookupPerPage + 1;
        const endIndex = Math.min(this.lookupCurrentPage * this.lookupPerPage, this.filteredLookupFiles.length);
        paginationInfo.textContent = `Showing ${startIndex}-${endIndex} of ${this.filteredLookupFiles.length} files`;

        const firstPageBtn = document.getElementById('lookupFirstPageBtn');
        const prevPageBtn = document.getElementById('lookupPrevPageBtn');
        const nextPageBtn = document.getElementById('lookupNextPageBtn');
        const lastPageBtn = document.getElementById('lookupLastPageBtn');

        firstPageBtn.disabled = this.lookupCurrentPage === 1;
        prevPageBtn.disabled = this.lookupCurrentPage === 1;
        nextPageBtn.disabled = this.lookupCurrentPage === totalPages;
        lastPageBtn.disabled = this.lookupCurrentPage === totalPages;

        this.updateLookupPageNumbers(totalPages);
    }

    updateLookupPageNumbers(totalPages) {
        const pageNumbersContainer = document.getElementById('lookupPageNumbers');
        pageNumbersContainer.innerHTML = '';

        if (totalPages <= 1) return;

        const maxVisiblePages = 5;
        let startPage = Math.max(1, this.lookupCurrentPage - Math.floor(maxVisiblePages / 2));
        let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);

        if (endPage - startPage < maxVisiblePages - 1) {
            startPage = Math.max(1, endPage - maxVisiblePages + 1);
        }

        if (startPage > 1) {
            this.addLookupPageNumber(pageNumbersContainer, 1);
            if (startPage > 2) {
                this.addEllipsis(pageNumbersContainer);
            }
        }

        for (let i = startPage; i <= endPage; i++) {
            this.addLookupPageNumber(pageNumbersContainer, i);
        }

        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                this.addEllipsis(pageNumbersContainer);
            }
            this.addLookupPageNumber(pageNumbersContainer, totalPages);
        }
    }

    addLookupPageNumber(container, pageNum) {
        const pageBtn = document.createElement('button');
        pageBtn.className = 'page-number';
        pageBtn.textContent = pageNum;

        if (pageNum === this.lookupCurrentPage) {
            pageBtn.classList.add('active');
        }

        pageBtn.addEventListener('click', () => {
            this.lookupCurrentPage = pageNum;
            this.displayLookupFiles();
        });

        container.appendChild(pageBtn);
    }

    showLookupPaginationIfNeeded() {
        const paginationContainer = document.getElementById('lookupPaginationContainer');
        const totalPages = this.getLookupTotalPages();

        if (this.lookupPerPage === 'all' || totalPages <= 1) {
            paginationContainer.style.display = 'none';
        } else {
            paginationContainer.style.display = 'block';
        }
    }

    hideLookupPagination() {
        const paginationContainer = document.getElementById('lookupPaginationContainer');
        if (paginationContainer) {
            paginationContainer.style.display = 'none';
        }
    }

    // Cross-Referencing Methods
    buildCrossReferences() {
        if (this.queries.length === 0 || this.lookupFiles.length === 0) return;

        this.queryToLookups = {};
        this.lookupToQueries = {};

        // Build a Set of CQL Hub lookup file names for fast matching
        const cqlHubNames = new Set(this.lookupFiles.map(f => f.name));
        const preSuppliedSet = new Set(this.preSuppliedLookupFiles);

        // Initialize lookupToQueries for all lookup files
        this.lookupFiles.forEach(file => {
            this.lookupToQueries[file.name] = [];
        });

        // Extract lookup file references from CQL using regex
        const matchFileRegex = /match\s*\(\s*file\s*=\s*"([^"]+)"/g;

        this.queries.forEach(query => {
            if (!query.cql) return;

            const cqlHub = [];
            const preSupplied = [];
            const missing = [];
            const seen = new Set();
            let match;

            while ((match = matchFileRegex.exec(query.cql)) !== null) {
                const filename = match[1];
                if (seen.has(filename)) continue;
                seen.add(filename);

                if (cqlHubNames.has(filename)) {
                    cqlHub.push(filename);
                } else if (preSuppliedSet.has(filename)) {
                    preSupplied.push(filename);
                } else {
                    missing.push(filename);
                }
            }

            if (cqlHub.length > 0 || preSupplied.length > 0 || missing.length > 0) {
                this.queryToLookups[query.name] = { cqlHub, preSupplied, missing };

                // Build reverse map only for CQL Hub files
                cqlHub.forEach(filename => {
                    if (this.lookupToQueries[filename]) {
                        this.lookupToQueries[filename].push(query);
                    }
                });
            }
        });
    }

    // Pagination Methods
    bindPaginationEvents() {
        const firstPageBtn = document.getElementById('firstPageBtn');
        const prevPageBtn = document.getElementById('prevPageBtn');
        const nextPageBtn = document.getElementById('nextPageBtn');
        const lastPageBtn = document.getElementById('lastPageBtn');

        // perPageSelect is now handled by standalone select logic

        if (firstPageBtn) {
            firstPageBtn.addEventListener('click', () => {
                this.currentPage = 1;
                this.displayQueries();
            });
        }

        if (prevPageBtn) {
            prevPageBtn.addEventListener('click', () => {
                if (this.currentPage > 1) {
                    this.currentPage--;
                    this.displayQueries();
                }
            });
        }

        if (nextPageBtn) {
            nextPageBtn.addEventListener('click', () => {
                const totalPages = this.getTotalPages();
                if (this.currentPage < totalPages) {
                    this.currentPage++;
                    this.displayQueries();
                }
            });
        }

        if (lastPageBtn) {
            lastPageBtn.addEventListener('click', () => {
                this.currentPage = this.getTotalPages();
                this.displayQueries();
            });
        }
    }

    getTotalPages() {
        if (this.queriesPerPage === 'all') return 1;
        return Math.ceil(this.filteredQueries.length / this.queriesPerPage);
    }

    updatePagination() {
        if (this.queriesPerPage === 'all') return;
        
        const totalPages = this.getTotalPages();
        
        // Update pagination info
        const paginationInfo = document.getElementById('paginationInfo');
        const startIndex = (this.currentPage - 1) * this.queriesPerPage + 1;
        const endIndex = Math.min(this.currentPage * this.queriesPerPage, this.filteredQueries.length);
        paginationInfo.textContent = `Showing ${startIndex}-${endIndex} of ${this.filteredQueries.length} queries`;
        
        // Update button states
        const firstPageBtn = document.getElementById('firstPageBtn');
        const prevPageBtn = document.getElementById('prevPageBtn');
        const nextPageBtn = document.getElementById('nextPageBtn');
        const lastPageBtn = document.getElementById('lastPageBtn');
        
        firstPageBtn.disabled = this.currentPage === 1;
        prevPageBtn.disabled = this.currentPage === 1;
        nextPageBtn.disabled = this.currentPage === totalPages;
        lastPageBtn.disabled = this.currentPage === totalPages;
        
        // Update page numbers
        this.updatePageNumbers(totalPages);
    }

    updatePageNumbers(totalPages) {
        const pageNumbersContainer = document.getElementById('pageNumbers');
        pageNumbersContainer.innerHTML = '';
        
        if (totalPages <= 1) return;
        
        const maxVisiblePages = 5;
        let startPage = Math.max(1, this.currentPage - Math.floor(maxVisiblePages / 2));
        let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
        
        // Adjust start page if we're near the end
        if (endPage - startPage < maxVisiblePages - 1) {
            startPage = Math.max(1, endPage - maxVisiblePages + 1);
        }
        
        // Add first page and ellipsis if needed
        if (startPage > 1) {
            this.addPageNumber(pageNumbersContainer, 1);
            if (startPage > 2) {
                this.addEllipsis(pageNumbersContainer);
            }
        }
        
        // Add visible page numbers
        for (let i = startPage; i <= endPage; i++) {
            this.addPageNumber(pageNumbersContainer, i);
        }
        
        // Add ellipsis and last page if needed
        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                this.addEllipsis(pageNumbersContainer);
            }
            this.addPageNumber(pageNumbersContainer, totalPages);
        }
    }

    addPageNumber(container, pageNum) {
        const pageBtn = document.createElement('button');
        pageBtn.className = 'page-number';
        pageBtn.textContent = pageNum;
        
        if (pageNum === this.currentPage) {
            pageBtn.classList.add('active');
        }
        
        pageBtn.addEventListener('click', () => {
            this.currentPage = pageNum;
            this.displayQueries();
        });
        
        container.appendChild(pageBtn);
    }

    addEllipsis(container) {
        const ellipsis = document.createElement('span');
        ellipsis.className = 'page-ellipsis';
        ellipsis.textContent = '...';
        container.appendChild(ellipsis);
    }

    showPaginationIfNeeded() {
        const paginationContainer = document.getElementById('paginationContainer');
        const totalPages = this.getTotalPages();
        
        if (this.queriesPerPage === 'all' || totalPages <= 1) {
            paginationContainer.style.display = 'none';
        } else {
            paginationContainer.style.display = 'block';
        }
    }

    hidePagination() {
        const paginationContainer = document.getElementById('paginationContainer');
        paginationContainer.style.display = 'none';
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new CQLHub();
});
