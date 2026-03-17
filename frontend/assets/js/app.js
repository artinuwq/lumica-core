const statusCard = document.getElementById("status-card");
        const statusTitle = document.getElementById("status-title");
        const statusText = document.getElementById("status-text");
        const appContent = document.getElementById("app-content");
        const welcomeTitle = document.getElementById("welcome-title");
        const statusLabel = document.getElementById("status-label");
        const pulseScene = document.getElementById("pulse-scene");
        const loading = document.getElementById("loading");
        const mainEl = document.querySelector("main");
        const orbWrapper = document.querySelector(".orb-wrapper");
        const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
        const navButtons = document.querySelectorAll("[data-screen]");
        const screens = document.querySelectorAll(".screen");
        const heroCardEl = document.getElementById("hero-card");
        const topbarEl = document.getElementById("topbar");
        const workSectionTitleEl = document.getElementById("work-section-title");
        const connectionsPageContextEl = document.getElementById("connections-page-context");
        const connectionsPageContextPillEl = document.getElementById("connections-page-context-pill");
        const workPageContextEl = document.getElementById("work-page-context");
        const workPageContextPillEl = document.getElementById("work-page-context-pill");
        const cloudPageContextEl = document.getElementById("cloud-page-context");
        const cloudPageContextPillEl = document.getElementById("cloud-page-context-pill");
        const screenMenuContextEl = document.getElementById("screen-menu-context");
        const screenMenuContextPillEl = document.getElementById("screen-menu-context-pill");
        const bottomNavEl = document.querySelector(".bottom-nav");
        const navSecondBtnEl = document.getElementById("nav-second-btn");
        const navSecondIconEl = document.getElementById("nav-second-icon");
        const navSecondLabelEl = document.getElementById("nav-second-label");
        const navWorkBtn = document.getElementById("nav-work-btn");
        const workPages = document.querySelectorAll("#screen-work .work-page");
        const workNavButtons = document.querySelectorAll("[data-work-nav]");
        const workBackButtons = document.querySelectorAll("[data-work-back]");
        const authUrl = `${window.location.origin}/api/tg/auth`;
        const meUrl = `${window.location.origin}/api/me`;
        const statusUrl = `${window.location.origin}/api/status`;
        const vpnConfigUrl = `${window.location.origin}/api/vpn/config`;
        const vpnHttpUrl = `${window.location.origin}/api/vpn/http`;
        const vpnMixedUrl = `${window.location.origin}/api/vpn/mixed`;
        const vpnSelectServerUrl = `${window.location.origin}/api/vpn/select-server`;
        const adminUsersUrl = `${window.location.origin}/api/admin/users`;
        const adminInboundsUrl = `${window.location.origin}/api/admin/inbounds`;
        const adminSyncInboundsUrl = `${window.location.origin}/api/admin/sync-inbounds`;
        const adminBindClientUrl = `${window.location.origin}/api/admin/bind-client`;
        const adminUnbindClientUrl = `${window.location.origin}/api/admin/unbind-client`;
        const adminPendingBindingsUrl = `${window.location.origin}/api/admin/pending-bindings`;
        const adminCancelPendingBindingUrl = (pendingId) =>
            `${window.location.origin}/api/admin/pending-bindings/${pendingId}/cancel`;
        const adminInboundVisibilityUrl = (panelInboundId) => `${window.location.origin}/api/admin/inbounds/${panelInboundId}/visibility`;
        const adminInboundClientsUrl = (panelInboundId) => `${window.location.origin}/api/admin/inbounds/${panelInboundId}/clients`;
        const adminUserBindingsUrl = (userId) => `${window.location.origin}/api/admin/users/${userId}/bindings`;
        const adminUserOverviewUrl = (userId) => `${window.location.origin}/api/admin/users/${userId}/overview`;
        const adminUserSubscriptionUrl = (userId) => `${window.location.origin}/api/admin/users/${userId}/subscription`;
        const adminUserOverviewByTelegramUrl = (telegramId) =>
            `${window.location.origin}/api/admin/users/by-telegram/${encodeURIComponent(telegramId)}/overview`;
        const adminUserSubscriptionByTelegramUrl = `${window.location.origin}/api/admin/users/by-telegram/subscription`;
        const adminSettingsUrl = `${window.location.origin}/api/admin/settings`;
        const adminSettingUrl = (settingKey) => `${adminSettingsUrl}/${encodeURIComponent(settingKey)}`;
        const adminPanelsUrl = `${window.location.origin}/api/admin/panels`;
        const adminPanelsTestUrl = `${window.location.origin}/api/admin/panels/test-connection`;
        const adminPanelUpdateUrl = (panelId) => `${adminPanelsUrl}/${encodeURIComponent(panelId)}`;
        const adminPanelActionUrl = (panelId, action) => `${adminPanelsUrl}/${encodeURIComponent(panelId)}/${action}`;
        const cloudListUrl = `${window.location.origin}/api/cloud/list`;
        const cloudMkdirUrl = `${window.location.origin}/api/cloud/mkdir`;
        const cloudUploadUrl = `${window.location.origin}/api/cloud/upload`;
        const cloudDeleteNodeUrl = (nodeId) => `${window.location.origin}/api/cloud/nodes/${nodeId}`;
        const cloudDownloadFileUrl = (fileId) => `${window.location.origin}/api/cloud/files/${fileId}/download`;
        const homeServerSub = document.getElementById("home-server-sub");
        const homeSubTitle = document.getElementById("home-sub-title");
        const homeSubSub = document.getElementById("home-sub-sub");
        const homeSubRight = document.getElementById("home-sub-right");
        const homeCloudBtnEl = document.getElementById("home-cloud-btn");
        const homeServerCardEl = document.getElementById("home-server-card");
        const homeConnectionsBtnEl = document.getElementById("home-connections-btn");
        const settingsNavSecondSelectEl = document.getElementById("settings-nav-second-select");
        const connectionsMenuPageEl = document.getElementById("connections-menu-page");
        const connectionsDetailPageEl = document.getElementById("connections-detail-page");
        const connectionsBackBtnEl = document.getElementById("connections-back-btn");
        const connectionsDetailTitleEl = document.getElementById("connections-detail-title");
        const connectionsDetailSubtitleEl = document.getElementById("connections-detail-subtitle");
        const connectionsDetailListEl = document.getElementById("connections-detail-list");
        const connectionProtocolButtons = document.querySelectorAll("[data-connection-protocol]");
        const vlessCardEl = document.getElementById("vless-card");
        const httpCardEl = document.getElementById("http-card");
        const mixedCardEl = document.getElementById("mixed-card");
        const connectionsHiddenNoteEl = document.getElementById("connections-hidden-note");
        const vlessStatusEl = document.getElementById("vless-status");
        const vlessDetailEl = document.getElementById("vless-detail");
        const httpStatusEl = document.getElementById("http-status");
        const httpDetailEl = document.getElementById("http-detail");
        const mixedStatusEl = document.getElementById("mixed-status");
        const mixedDetailEl = document.getElementById("mixed-detail");
        const profileTelegramIdEl = document.getElementById("profile-telegram-id");
        const profileIdToggleEl = document.getElementById("profile-id-toggle");
        const profileSubTitleEl = document.getElementById("profile-sub-title");
        const profileSubSubEl = document.getElementById("profile-sub-sub");
        const profileRoleEl = document.getElementById("profile-role");
        const profileReferralCardEl = document.getElementById("profile-referral-card");
        const profileReferralInputCardEl = document.getElementById("profile-referral-input-card");
        const profileReferralCodeEl = document.getElementById("profile-referral-code");
        const profileReferralApplyEl = document.getElementById("profile-referral-apply");
        const profileReferralStatusCardEl = document.getElementById("profile-referral-status-card");
        const profileReferralStatusEl = document.getElementById("profile-referral-status");
        const profileReferralStatusTitleEl = document.getElementById("profile-referral-status-title");
        const workOwnerNameEl = document.getElementById("work-owner-name");
        const workOwnerRoleEl = document.getElementById("work-owner-role");
        const workRolePillEl = document.getElementById("work-role-pill");
        const workSettingsRefreshBtnEl = document.getElementById("work-settings-refresh-btn");
        const workSettingsSaveBtnEl = document.getElementById("work-settings-save-btn");
        const workSettingsSaveStatusEl = document.getElementById("work-settings-save-status");
        const workSettingCloudVisibilityEl = document.getElementById("work-setting-cloud-visibility");
        const workSettingCloudChunkMbEl = document.getElementById("work-setting-cloud-chunk-mb");
        const workSettingCloudSendTimeoutEl = document.getElementById("work-setting-cloud-send-timeout");
        const workSettingCloudSendRetriesEl = document.getElementById("work-setting-cloud-send-retries");
        const workSettingCloudSendRetryDelayEl = document.getElementById("work-setting-cloud-send-retry-delay");
        const workPanelsListEl = document.getElementById("work-panels-list");
        const workPanelNameEl = document.getElementById("work-panel-name");
        const workPanelProviderEl = document.getElementById("work-panel-provider");
        const workPanelBaseUrlEl = document.getElementById("work-panel-base-url");
        const workPanelRegionEl = document.getElementById("work-panel-region");
        const workPanelUsernameEl = document.getElementById("work-panel-username");
        const workPanelPasswordEl = document.getElementById("work-panel-password");
        const workPanelTestBtnEl = document.getElementById("work-panel-test-btn");
        const workPanelSaveBtnEl = document.getElementById("work-panel-save-btn");
        const workPanelStatusEl = document.getElementById("work-panel-status");
        const workPanelDetailTitleEl = document.getElementById("work-panel-detail-title");
        const workPanelDetailMetaEl = document.getElementById("work-panel-detail-meta");
        const workPanelDetailBadgesEl = document.getElementById("work-panel-detail-badges");
        const workPanelDetailSummaryEl = document.getElementById("work-panel-detail-summary");
        const workPanelDetailActivateBtnEl = document.getElementById("work-panel-detail-activate-btn");
        const workPanelDetailSyncBtnEl = document.getElementById("work-panel-detail-sync-btn");
        const workPanelDetailAccessBtnEl = document.getElementById("work-panel-detail-access-btn");
        const workPanelDetailAccessWrapEl = document.getElementById("work-panel-detail-access-wrap");
        const workPanelDetailBaseUrlEl = document.getElementById("work-panel-detail-base-url");
        const workPanelDetailUsernameEl = document.getElementById("work-panel-detail-username");
        const workPanelDetailPasswordEl = document.getElementById("work-panel-detail-password");
        const workPanelDetailTestBtnEl = document.getElementById("work-panel-detail-test-btn");
        const workPanelDetailSaveBtnEl = document.getElementById("work-panel-detail-save-btn");
        const workPanelDetailDeleteBtnEl = document.getElementById("work-panel-detail-delete-btn");
        const workPanelDetailStatusEl = document.getElementById("work-panel-detail-status");
        const workPanelDetailInboundsListEl = document.getElementById("work-panel-detail-inbounds-list");
        const workInboundsListEl = document.getElementById("work-inbounds-list");
        const workInboundDetailTitleEl = document.getElementById("work-inbound-detail-title");
        const workInboundDetailMetaEl = document.getElementById("work-inbound-detail-meta");
        const workInboundDetailBadgesEl = document.getElementById("work-inbound-detail-badges");
        const workInboundDetailToggleBtnEl = document.getElementById("work-inbound-detail-toggle-btn");
        const workInboundDetailNoteEl = document.getElementById("work-inbound-detail-note");
        const workInboundDetailClientsListEl = document.getElementById("work-inbound-detail-clients-list");
        const workInboundDetailNewClientLabelEl = document.getElementById("work-inbound-detail-new-client-label");
        const workInboundDetailAddClientBtnEl = document.getElementById("work-inbound-detail-add-client-btn");
        const workInboundDetailAddStatusEl = document.getElementById("work-inbound-detail-add-status");
        const workClientCardsEl = document.getElementById("work-client-cards");
        const workClientSearchEl = document.getElementById("work-client-search");
        const workClientPageTitleEl = document.getElementById("work-client-page-title");
        const workClientNameEl = document.getElementById("work-client-name");
        const workClientMetaEl = document.getElementById("work-client-meta");
        const workClientSubStatusEl = document.getElementById("work-client-sub-status");
        const workClientSubUntilEl = document.getElementById("work-client-sub-until");
        const workClientSubPriceEl = document.getElementById("work-client-sub-price");
        const workClientConnectionsAvailableEl = document.getElementById("work-client-connections-available");
        const workExistingLinksEl = document.getElementById("work-existing-links");
        const workInboundSelectEl = document.getElementById("work-inbound-select");
        const workClientSelectEl = document.getElementById("work-client-select");
        const workBindBtnEl = document.getElementById("work-bind-btn");
        const workRefreshInboundClientsBtnEl = document.getElementById("work-refresh-inbound-clients-btn");
        const workPendingTelegramIdEl = document.getElementById("work-pending-telegram-id");
        const workPendingInboundSelectEl = document.getElementById("work-pending-inbound-select");
        const workPendingClientSelectEl = document.getElementById("work-pending-client-select");
        const workPendingAddBtnEl = document.getElementById("work-pending-add-btn");
        const workPendingListEl = document.getElementById("work-pending-list");
        const workPendingSubStatusSelectEl = document.getElementById("work-pending-sub-status-select");
        const workPendingSubPriceInputEl = document.getElementById("work-pending-sub-price-input");
        const workPendingSubLimitInputEl = document.getElementById("work-pending-sub-limit-input");
        const workPendingSubCreateWrapEl = document.getElementById("work-pending-sub-create-wrap");
        const workPendingSubCreateDateEl = document.getElementById("work-pending-sub-create-date");
        const workPendingSubSaveBtnEl = document.getElementById("work-pending-sub-save-btn");
        const workPendingSubSaveStatusEl = document.getElementById("work-pending-sub-save-status");
        const workSubStatusSelectEl = document.getElementById("work-sub-status-select");
        const workSubPriceInputEl = document.getElementById("work-sub-price-input");
        const workSubLimitInputEl = document.getElementById("work-sub-limit-input");
        const workSubSaveBtnEl = document.getElementById("work-sub-save-btn");
        const workSubExtendWrapEl = document.getElementById("work-sub-extend-wrap");
        const workSubCreateWrapEl = document.getElementById("work-sub-create-wrap");
        const workSubCreateDateEl = document.getElementById("work-sub-create-date");
        const workSubExtendRangeEl = document.getElementById("work-sub-extend-range");
        const workSubExtendValueEl = document.getElementById("work-sub-extend-value");
        const workSubExtendBtnEl = document.getElementById("work-sub-extend-btn");
        const cloudUpBtnEl = document.getElementById("cloud-up-btn");
        const cloudNewFolderBtnEl = document.getElementById("cloud-new-folder-btn");
        const cloudUploadInputEl = document.getElementById("cloud-upload-input");
        const cloudUploadLabelEl = document.getElementById("cloud-upload-label");
        const cloudUploadProgressEl = document.getElementById("cloud-upload-progress");
        const cloudUploadProgressBarEl = document.getElementById("cloud-upload-progress-bar");
        const cloudUploadProgressTextEl = document.getElementById("cloud-upload-progress-text");
        const cloudPathEl = document.getElementById("cloud-path");
        const cloudStatusNoteEl = document.getElementById("cloud-status-note");
        const cloudListEl = document.getElementById("cloud-list");
        const cloudPreviewOverlayEl = document.getElementById("cloud-preview-overlay");
        const cloudPreviewCardEl = document.getElementById("cloud-preview-card");
        const cloudPreviewTitleEl = document.getElementById("cloud-preview-title");
        const cloudPreviewCloseBtnEl = document.getElementById("cloud-preview-close-btn");
        const cloudPreviewMediaWrapEl = document.getElementById("cloud-preview-media-wrap");
        const cloudPreviewNoteEl = document.getElementById("cloud-preview-note");
        const vlessGuideOverlayEl = document.getElementById("vless-guide-overlay");
        const vlessGuideCardEl = document.getElementById("vless-guide-card");
        const vlessGuideHideBtnEl = document.getElementById("vless-guide-hide-btn");
        const vlessGuideHideCheckboxEl = document.getElementById("vless-guide-hide-checkbox");
        const vlessGuideTextEl = document.getElementById("vless-guide-text");
        const systemSettingKeys = {
            cloudVisibility: "cloud.visibility",
            cloudChunkSizeMb: "cloud.upload.chunk_size_mb",
            cloudSendTimeoutSec: "cloud.telegram.send.timeout_sec",
            cloudSendRetries: "cloud.telegram.send.retries",
            cloudSendRetryDelaySec: "cloud.telegram.send.retry_delay_sec",
        };
        const workState = {
            users: [],
            inbounds: [],
            clients: [],
            bindings: [],
            pendingClients: [],
            pendingBindings: [],
            pendingOverview: null,
            settings: {},
            panels: [],
            selectedUserId: null,
            overview: null,
            selectedInboundPanelId: null,
            selectedPanelId: null,
        };
        const FORCE_HIDE_TOPBAR = true;
        const FULLSCREEN_TOP_RESERVE_PX = 28;
        const FULLSCREEN_BOTTOM_RESERVE_PX = 2;
        const connectionsState = {
            activeProtocol: null,
            entries: {
                vless: [],
                http: [],
                mixed: [],
            },
            visibility: {
                vless: false,
                http: false,
                mixed: false,
            },
        };
        const cloudState = {
            path: "/",
            folders: [],
            files: [],
            initialized: false,
            isUploading: false,
        };
        const uiFeatures = {
            cloudEnabled: true,
        };
        const NAV_SECOND_ITEM_KEY = "nav_second_item";
        const VLESS_GUIDE_HIDE_KEY = "vless_guide_hide";
        const navSecondButtonByKey = {
            connections: {
                key: "connections",
                screen: "screen-connections",
                icon: "⬇️",
                label: "Подключения",
            },
            cloud: {
                key: "cloud",
                screen: "screen-cloud",
                icon: "☁️",
                label: "Облако",
            },
        };
        const navPreference = {
            secondItem: "connections",
        };
        const vlessGuidePreference = {
            dontShow: false,
            loaded: false,
        };
        let lastUserPayload = null;
        let isVerifiedUser = true;
        let csrfToken = "";
        let showFullTelegramId = false;
        let viewportListenerBound = false;
        let tgBackButtonBound = false;
        let screenMenuActionBusy = false;
        let screenMenuActionCurrent = "";
        let workPageActionBusy = false;
        let workPageActionCurrent = "";
        const workBackTargetByPage = new Map();
        workBackButtons.forEach((btn) => {
            const pageId = btn.closest(".work-page")?.id;
            if (!pageId) return;
            workBackTargetByPage.set(pageId, btn.dataset.workBack || "work-menu-page");
        });
        const workContextTitleByPage = new Map([
            ["work-staff-page", "Персонал"],
            ["work-clients-page", "Клиенты"],
            ["work-inbounds-page", "Подключения"],
            ["work-inbound-detail-page", "Подключение"],
            ["work-system-settings-page", "Системные настройки"],
            ["work-panels-page", "Панели"],
            ["work-panel-create-page", "Новая панель"],
            ["work-panel-detail-page", "Панель"],
            ["work-client-page", "Клиент"],
            ["work-client-connections-page", "Подключения"],
            ["work-client-subscription-page", "Подписка"],
        ]);
        const menuContextTitleByScreen = new Map([
            ["screen-connections", "Подключения"],
            ["screen-cloud", "Облако"],
            ["screen-work", "Работа"],
            ["screen-profile", "Профиль"],
            ["screen-settings", "Настройки"],
        ]);
        const cloudAudioExtensions = new Set(["mp3", "m4a", "aac", "ogg", "opus", "wav", "flac", "alac", "wma", "amr", "mid", "midi"]);
        const cloudVideoExtensions = new Set(["mp4", "m4v", "mov", "mkv", "webm", "avi", "wmv", "flv", "mpeg", "mpg", "3gp", "ts"]);
        const cloudImageExtensions = new Set(["jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff", "tif", "svg", "heic", "heif", "ico", "avif"]);
        const cloudArchiveExtensions = new Set(["zip", "rar", "7z", "tar", "gz", "bz2", "xz", "tgz", "tbz", "txz", "zst"]);
        const cloudDocumentExtensions = new Set(["doc", "docx", "odt", "pages"]);
        const cloudSheetExtensions = new Set(["xls", "xlsx", "ods", "csv", "tsv", "numbers"]);
        const cloudSlideExtensions = new Set(["ppt", "pptx", "odp", "key"]);
        const cloudCodeExtensions = new Set([
            "py",
            "js",
            "ts",
            "jsx",
            "tsx",
            "html",
            "htm",
            "css",
            "scss",
            "sass",
            "less",
            "json",
            "xml",
            "yaml",
            "yml",
            "toml",
            "ini",
            "cfg",
            "env",
            "sh",
            "bat",
            "ps1",
            "sql",
            "go",
            "rs",
            "java",
            "kt",
            "c",
            "h",
            "cpp",
            "hpp",
            "cs",
            "php",
            "rb",
            "swift",
            "dart",
            "lua",
        ]);

        function isMobileTelegramPlatform(tg) {
            const platform = String(tg?.platform || "").toLowerCase();
            return platform === "android" || platform === "ios";
        }

        function updateSafeAreaVars(tg) {
            const safeArea = tg?.safeAreaInset || tg?.contentSafeAreaInset;
            const top = Number(safeArea?.top) || 0;
            const bottom = Number(safeArea?.bottom) || 0;
            document.documentElement.style.setProperty("--safe-top", `${top}px`);
            document.documentElement.style.setProperty("--safe-bottom", `${bottom}px`);
        }

        function applyTopReserve(enabled) {
            const reserve = enabled ? FULLSCREEN_TOP_RESERVE_PX : 0;
            document.documentElement.style.setProperty("--system-top-reserve", `${reserve}px`);
        }

        function applyBottomReserve(enabled) {
            const reserve = enabled ? FULLSCREEN_BOTTOM_RESERVE_PX : 0;
            document.documentElement.style.setProperty("--system-nav-reserve", `${reserve}px`);
        }

        function ensureSafeViewportMode() {
            const tg = window.Telegram?.WebApp;
            if (!tg) {
                applyTopReserve(false);
                applyBottomReserve(false);
                return;
            }
            try {
                const isMobile = isMobileTelegramPlatform(tg);
                const canFullscreen = isMobile && typeof tg.requestFullscreen === "function" && tg.isVersionAtLeast?.("8.0");
                updateSafeAreaVars(tg);
                tg.expand?.();
                if (canFullscreen) {
                    try {
                        tg.requestFullscreen();
                    } catch (fullscreenErr) {
                        console.warn("requestFullscreen failed:", fullscreenErr);
                    }
                }
                applyTopReserve(Boolean(tg.isFullscreen) || canFullscreen);
                applyBottomReserve(Boolean(tg.isFullscreen) || canFullscreen);

                if (!viewportListenerBound && typeof tg.onEvent === "function") {
                    tg.onEvent("viewportChanged", () => {
                        updateSafeAreaVars(tg);
                        applyTopReserve(Boolean(tg.isFullscreen) || canFullscreen);
                        applyBottomReserve(Boolean(tg.isFullscreen) || canFullscreen);
                    });
                    viewportListenerBound = true;
                }
            } catch (err) {
                console.error("viewport mode setup error:", err);
            }
        }

        function setTopbarVisibility(shouldHide = false) {
            if (!topbarEl) return;
            if (FORCE_HIDE_TOPBAR || shouldHide) {
                topbarEl.classList.add("hidden");
            } else {
                topbarEl.classList.remove("hidden");
            }
        }

        function getActiveScreenId() {
            const active = Array.from(screens).find((screen) => !screen.classList.contains("hidden"));
            return active?.id || "";
        }

        function getActiveWorkPageId() {
            const active = Array.from(workPages).find((page) => !page.classList.contains("hidden"));
            return active?.id || "";
        }

        function updateScreenMenuContext(screenId = getActiveScreenId()) {
            if (!screenMenuContextEl || !screenMenuContextPillEl) return;
            let title = "";
            let action = "";

            if (screenId === "screen-connections" && connectionsDetailPageEl?.classList.contains("hidden")) {
                title = menuContextTitleByScreen.get("screen-connections") || "";
                action = "refresh-connections";
            } else if (screenId === "screen-cloud") {
                title = menuContextTitleByScreen.get("screen-cloud") || "";
                action = "refresh-cloud";
            } else if (screenId === "screen-work" && getActiveWorkPageId() === "work-menu-page") {
                title = menuContextTitleByScreen.get("screen-work") || "";
            } else if (screenId === "screen-profile") {
                title = menuContextTitleByScreen.get("screen-profile") || "";
            } else if (screenId === "screen-settings") {
                title = menuContextTitleByScreen.get("screen-settings") || "";
            }

            if (!title) {
                screenMenuContextEl.dataset.action = "";
                screenMenuContextEl.classList.remove("clickable");
                screenMenuContextPillEl.tabIndex = -1;
                screenMenuContextPillEl.removeAttribute("role");
                screenMenuContextEl.classList.add("hidden");
                return;
            }

            const isBusyForAction = Boolean(action) && screenMenuActionBusy && action === screenMenuActionCurrent;
            const displayTitle = isBusyForAction
                ? `${title} ⏳`
                : action
                    ? `${title} 🔄`
                    : title;

            screenMenuContextEl.dataset.action = action || "";
            screenMenuContextEl.classList.toggle("clickable", Boolean(action) && !screenMenuActionBusy);
            screenMenuContextPillEl.tabIndex = Boolean(action) && !screenMenuActionBusy ? 0 : -1;
            if (action) {
                screenMenuContextPillEl.setAttribute("role", "button");
            } else {
                screenMenuContextPillEl.removeAttribute("role");
            }
            screenMenuContextPillEl.textContent = displayTitle;
            screenMenuContextPillEl.title = displayTitle;
            screenMenuContextEl.classList.remove("hidden");
        }

        async function runScreenMenuContextAction() {
            const action = String(screenMenuContextEl?.dataset?.action || "").trim();
            if (!action || screenMenuActionBusy) {
                return;
            }

            screenMenuActionBusy = true;
            screenMenuActionCurrent = action;
            updateScreenMenuContext(getActiveScreenId());

            try {
                if (action === "refresh-cloud") {
                    await ensureCloudLoaded(true);
                } else if (action === "refresh-connections") {
                    const runtime = await loadRuntimeData();
                    renderDashboard(runtime);
                }
            } catch (err) {
                console.error("screen menu action error:", err);
                if (action === "refresh-cloud") {
                    setCloudStatus(err?.message || "Не удалось обновить файлы", "error");
                }
            } finally {
                screenMenuActionBusy = false;
                screenMenuActionCurrent = "";
                updateScreenMenuContext(getActiveScreenId());
            }
        }

        function resolveWorkContextTitle(pageId) {
            if (pageId === "work-client-page") {
                const dynamicTitle = String(workClientPageTitleEl?.textContent || "").trim();
                return dynamicTitle || "Клиент";
            }
            if (pageId === "work-inbound-detail-page") {
                const dynamicTitle = String(workInboundDetailTitleEl?.textContent || "").trim();
                return dynamicTitle || "Подключение";
            }
            if (pageId === "work-panel-detail-page") {
                const dynamicTitle = String(workPanelDetailTitleEl?.textContent || "").trim();
                return dynamicTitle || "Панель";
            }
            return workContextTitleByPage.get(pageId) || "";
        }

        function resolveWorkContextAction(pageId) {
            if (pageId === "work-clients-page") {
                return "refresh-work-clients";
            }
            if (pageId === "work-inbounds-page") {
                return "sync-work-inbounds";
            }
            if (pageId === "work-panels-page") {
                return "refresh-work-panels";
            }
            if (pageId === "work-inbound-detail-page") {
                return "";
            }
            if (pageId === "work-panel-detail-page" || pageId === "work-panel-create-page") {
                return "";
            }
            if (!workState.selectedUserId) {
                return "";
            }
            if (
                pageId === "work-client-page"
                || pageId === "work-client-connections-page"
                || pageId === "work-client-subscription-page"
            ) {
                return "refresh-work-client";
            }
            return "";
        }

        function updateWorkPageContext(pageId) {
            if (!workPageContextEl || !workPageContextPillEl) return;
            if (!pageId || pageId === "work-menu-page") {
                workPageContextEl.dataset.action = "";
                workPageContextEl.classList.remove("clickable");
                workPageContextPillEl.tabIndex = -1;
                workPageContextPillEl.removeAttribute("role");
                workPageContextEl.classList.add("hidden");
                return;
            }
            const title = resolveWorkContextTitle(pageId);
            if (!title) {
                workPageContextEl.dataset.action = "";
                workPageContextEl.classList.remove("clickable");
                workPageContextPillEl.tabIndex = -1;
                workPageContextPillEl.removeAttribute("role");
                workPageContextEl.classList.add("hidden");
                return;
            }
            const action = resolveWorkContextAction(pageId);
            const isBusyForAction = Boolean(action) && workPageActionBusy && action === workPageActionCurrent;
            const displayTitle = isBusyForAction
                ? `${title} ⟳`
                : action
                    ? `${title} 🔄`
                    : title;

            workPageContextEl.dataset.action = action || "";
            workPageContextEl.classList.toggle("clickable", Boolean(action) && !workPageActionBusy);
            workPageContextPillEl.tabIndex = Boolean(action) && !workPageActionBusy ? 0 : -1;
            if (action) {
                workPageContextPillEl.setAttribute("role", "button");
            } else {
                workPageContextPillEl.removeAttribute("role");
            }
            workPageContextPillEl.textContent = displayTitle;
            workPageContextPillEl.title = displayTitle;
            workPageContextEl.classList.remove("hidden");
        }

        async function runWorkPageContextAction() {
            const action = String(workPageContextEl?.dataset?.action || "").trim();
            if (!action || workPageActionBusy) {
                return;
            }

            workPageActionBusy = true;
            workPageActionCurrent = action;
            updateWorkPageContext(getActiveWorkPageId());

            try {
                if (action === "refresh-work-clients") {
                    await loadWorkClientsData();
                } else if (action === "sync-work-inbounds") {
                    await postJson(adminSyncInboundsUrl);
                    const inboundsResp = await fetchJson(adminInboundsUrl, false);
                    workState.inbounds = Array.isArray(inboundsResp?.inbounds) ? inboundsResp.inbounds : [];
                    renderWorkInboundsManager();
                    renderWorkInboundSelectOptions();
                } else if (action === "refresh-work-panels") {
                    await loadWorkPanels();
                } else if (action === "refresh-work-client") {
                    const tasks = [
                        loadSelectedUserBindings(),
                        loadSelectedUserOverview(),
                    ];
                    if (workInboundSelectEl?.value) {
                        tasks.push(loadInboundClients(workInboundSelectEl.value));
                    }
                    const pendingTgId = workPendingTelegramIdEl?.value?.trim();
                    if (pendingTgId) {
                        tasks.push(loadPendingBindings(pendingTgId));
                        tasks.push(loadPendingSubscriptionOverview(pendingTgId));
                    }
                    await Promise.all(tasks);
                }
            } catch (err) {
                console.error("work page context action error:", err);
            } finally {
                workPageActionBusy = false;
                workPageActionCurrent = "";
                updateWorkPageContext(getActiveWorkPageId());
            }
        }

        function updateConnectionsPageContext(protocol) {
            if (!connectionsPageContextEl || !connectionsPageContextPillEl) return;
            if (!protocol) {
                connectionsPageContextEl.classList.add("hidden");
                return;
            }
            const title = connectionProtocolTitle(protocol);
            connectionsPageContextPillEl.textContent = title;
            connectionsPageContextPillEl.title = title;
            connectionsPageContextEl.classList.remove("hidden");
        }

        function cloudPathParts(path) {
            if (!path || path === "/") return [];
            return String(path)
                .split("/")
                .map((part) => part.trim())
                .filter(Boolean);
        }

        function normalizeCloudPath(rawPath) {
            const value = String(rawPath || "/").replace(/\\/g, "/").trim();
            if (!value || value === "/") return "/";
            const parts = value
                .split("/")
                .map((part) => part.trim())
                .filter((part) => part && part !== "." && part !== "..");
            return parts.length ? `/${parts.join("/")}` : "/";
        }

        function cloudParentPath(path) {
            const parts = cloudPathParts(path);
            if (!parts.length) return "/";
            parts.pop();
            return parts.length ? `/${parts.join("/")}` : "/";
        }

        function cloudContextTitle(path) {
            const parts = cloudPathParts(path);
            return parts.length ? parts[parts.length - 1] : "Облако";
        }

        function updateCloudPageContext(path) {
            if (!cloudPageContextEl) return;
            cloudPageContextEl.classList.add("hidden");
        }

        function normalizeNavSecondItemKey(rawValue) {
            const value = String(rawValue || "").trim().toLowerCase();
            return value === "cloud" ? "cloud" : "connections";
        }

        function getTelegramCloudStorageApi() {
            return window.Telegram?.WebApp?.CloudStorage || null;
        }

        function cloudStorageGetItem(key) {
            return new Promise((resolve, reject) => {
                const api = getTelegramCloudStorageApi();
                if (!api || typeof api.getItem !== "function") {
                    resolve(null);
                    return;
                }
                try {
                    api.getItem(String(key), (error, value) => {
                        if (error) {
                            reject(new Error(String(error)));
                            return;
                        }
                        resolve(value ?? null);
                    });
                } catch (err) {
                    reject(err);
                }
            });
        }

        function cloudStorageSetItem(key, value) {
            return new Promise((resolve, reject) => {
                const api = getTelegramCloudStorageApi();
                if (!api || typeof api.setItem !== "function") {
                    resolve(false);
                    return;
                }
                try {
                    api.setItem(String(key), String(value), (error) => {
                        if (error) {
                            reject(new Error(String(error)));
                            return;
                        }
                        resolve(true);
                    });
                } catch (err) {
                    reject(err);
                }
            });
        }

        function resolveEffectiveNavSecondItemKey() {
            if (!isVerifiedUser) {
                return "cloud";
            }
            const selected = normalizeNavSecondItemKey(navPreference.secondItem);
            if (selected === "cloud" && !uiFeatures.cloudEnabled) {
                return "connections";
            }
            return selected;
        }

        function applyNavSecondButtonConfig() {
            const effectiveKey = resolveEffectiveNavSecondItemKey();
            const config = navSecondButtonByKey[effectiveKey] || navSecondButtonByKey.connections;
            if (navSecondBtnEl) {
                navSecondBtnEl.dataset.screen = config.screen;
                navSecondBtnEl.title = config.label;
                navSecondBtnEl.classList.remove("hidden");
            }
            if (navSecondIconEl) {
                navSecondIconEl.textContent = config.icon;
            }
            if (navSecondLabelEl) {
                navSecondLabelEl.textContent = config.label;
            }
            if (settingsNavSecondSelectEl) {
                const cloudOption = settingsNavSecondSelectEl.querySelector('option[value="cloud"]');
                if (cloudOption) {
                    cloudOption.disabled = !uiFeatures.cloudEnabled;
                }
                if (!isVerifiedUser) {
                    settingsNavSecondSelectEl.value = "cloud";
                    settingsNavSecondSelectEl.disabled = true;
                } else {
                    settingsNavSecondSelectEl.disabled = false;
                    settingsNavSecondSelectEl.value = normalizeNavSecondItemKey(navPreference.secondItem);
                }
            }
            const activeScreenId = getActiveScreenId();
            navButtons.forEach((btn) => btn.classList.toggle("active", btn.dataset.screen === activeScreenId));
        }

        async function loadNavSecondPreference() {
            let storedValue = null;
            try {
                storedValue = window.localStorage?.getItem(NAV_SECOND_ITEM_KEY) || null;
            } catch (_err) {
                storedValue = null;
            }

            try {
                const cloudValue = await cloudStorageGetItem(NAV_SECOND_ITEM_KEY);
                if (typeof cloudValue === "string" && cloudValue.trim()) {
                    storedValue = cloudValue;
                }
            } catch (err) {
                console.warn("CloudStorage get nav_second_item failed:", err);
            }

            navPreference.secondItem = normalizeNavSecondItemKey(storedValue);
            applyNavSecondButtonConfig();
        }

        async function saveNavSecondPreference(nextValue) {
            const normalized = normalizeNavSecondItemKey(nextValue);
            navPreference.secondItem = normalized;
            applyNavSecondButtonConfig();
            try {
                window.localStorage?.setItem(NAV_SECOND_ITEM_KEY, normalized);
            } catch (_err) {
                // ignore localStorage failures
            }
            try {
                await cloudStorageSetItem(NAV_SECOND_ITEM_KEY, normalized);
            } catch (err) {
                console.warn("CloudStorage set nav_second_item failed:", err);
            }
        }

        function normalizeVlessGuideHideValue(rawValue) {
            const value = String(rawValue || "").trim().toLowerCase();
            return value === "1" || value === "true" || value === "yes" || value === "on";
        }

        function applyVlessGuidePreference(dontShow) {
            vlessGuidePreference.dontShow = Boolean(dontShow);
            if (vlessGuideHideCheckboxEl) {
                vlessGuideHideCheckboxEl.checked = vlessGuidePreference.dontShow;
            }
        }

        async function loadVlessGuidePreference() {
            if (vlessGuidePreference.loaded) {
                applyVlessGuidePreference(vlessGuidePreference.dontShow);
                return vlessGuidePreference.dontShow;
            }

            let storedValue = null;
            try {
                storedValue = window.localStorage?.getItem(VLESS_GUIDE_HIDE_KEY) || null;
            } catch (_err) {
                storedValue = null;
            }

            try {
                const cloudValue = await cloudStorageGetItem(VLESS_GUIDE_HIDE_KEY);
                if (typeof cloudValue === "string" && cloudValue.trim()) {
                    storedValue = cloudValue;
                }
            } catch (err) {
                console.warn("CloudStorage get vless_guide_hide failed:", err);
            }

            const resolvedValue = normalizeVlessGuideHideValue(storedValue);
            vlessGuidePreference.loaded = true;
            applyVlessGuidePreference(resolvedValue);
            return resolvedValue;
        }

        async function saveVlessGuidePreference(dontShow) {
            applyVlessGuidePreference(dontShow);
            vlessGuidePreference.loaded = true;
            const encoded = dontShow ? "1" : "0";

            try {
                window.localStorage?.setItem(VLESS_GUIDE_HIDE_KEY, encoded);
            } catch (_err) {
                // ignore localStorage failures
            }

            try {
                await cloudStorageSetItem(VLESS_GUIDE_HIDE_KEY, encoded);
            } catch (err) {
                console.warn("CloudStorage set vless_guide_hide failed:", err);
            }
        }

        function applyCloudVisibility(me) {
            const enabled = me?.features?.cloud_enabled !== false;
            uiFeatures.cloudEnabled = enabled;
            homeCloudBtnEl?.classList.toggle("hidden", !enabled);
            applyNavSecondButtonConfig();
            if (!enabled) {
                cloudPageContextEl?.classList.add("hidden");
                if (getActiveScreenId() === "screen-cloud") {
                    switchScreen("screen-home");
                }
            }
        }

        function updateCloudUpButton() {
            if (!cloudUpBtnEl) return;
            const canGoUp = normalizeCloudPath(cloudState.path) !== "/";
            const hideForTelegramBack = hasTelegramBackButton();
            cloudUpBtnEl.classList.toggle("hidden", !canGoUp || hideForTelegramBack);
        }

        function hasTelegramBackButton() {
            const backButton = window.Telegram?.WebApp?.BackButton;
            return Boolean(backButton && typeof backButton.show === "function" && typeof backButton.hide === "function");
        }

        function setCustomBackButtonsVisibility(visible) {
            workBackButtons.forEach((btn) => btn.classList.toggle("hidden", !visible));
            connectionsBackBtnEl?.classList.toggle("hidden", !visible);
            if (!visible) {
                cloudUpBtnEl?.classList.add("hidden");
                return;
            }
            updateCloudUpButton();
        }

        function handleTelegramBack() {
            const activeScreenId = getActiveScreenId();
            if (
                activeScreenId === "screen-cloud"
                && cloudPreviewOverlayEl
                && !cloudPreviewOverlayEl.classList.contains("hidden")
            ) {
                closeCloudPreview();
                return;
            }
            if (activeScreenId === "screen-connections" && !connectionsDetailPageEl?.classList.contains("hidden")) {
                openConnectionsMenu();
                return;
            }
            if (activeScreenId === "screen-connections") {
                switchScreen("screen-home");
                return;
            }

            if (activeScreenId === "screen-cloud") {
                if (normalizeCloudPath(cloudState.path) !== "/") {
                    loadCloudPath(cloudParentPath(cloudState.path)).catch((err) => {
                        console.error("cloud back error:", err);
                    });
                    return;
                }
                switchScreen("screen-home");
                return;
            }
            if (activeScreenId === "screen-settings") {
                switchScreen("screen-profile");
                return;
            }

            if (activeScreenId === "screen-work") {
                const activePageId = getActiveWorkPageId();
                const backTarget = workBackTargetByPage.get(activePageId);
                if (backTarget) {
                    switchWorkPage(backTarget);
                }
            }
        }

        function shouldShowTelegramBackButton() {
            const activeScreenId = getActiveScreenId();

            if (activeScreenId === "screen-connections") {
                return true;
            }

            if (activeScreenId === "screen-work") {
                const activePageId = getActiveWorkPageId();
                return Boolean(workBackTargetByPage.get(activePageId));
            }

            if (activeScreenId === "screen-cloud") {
                return true;
            }
            if (activeScreenId === "screen-settings") {
                return true;
            }

            return false;
        }

        function updateTelegramBackButton() {
            const backButton = window.Telegram?.WebApp?.BackButton;
            if (!backButton) return;

            const shouldShow = shouldShowTelegramBackButton();
            if (shouldShow) {
                if (!tgBackButtonBound && typeof backButton.onClick === "function") {
                    backButton.onClick(handleTelegramBack);
                    tgBackButtonBound = true;
                }
                backButton.show?.();
                return;
            }

            backButton.hide?.();
            updateCloudUpButton();
        }

        function syncBackNavigationMode() {
            const useTelegramBack = hasTelegramBackButton();
            document.body.classList.toggle("context-near-system-bar", useTelegramBack);
            setCustomBackButtonsVisibility(!useTelegramBack);
            if (useTelegramBack) {
                updateTelegramBackButton();
            }
            updateCloudUpButton();
        }

        function runRevealAnimation() {
            return new Promise((resolve) => {
                if (!orbWrapper) return resolve();
                const done = () => {
                    orbWrapper.removeEventListener("animationend", done);
                    resolve();
                };
                orbWrapper.addEventListener("animationend", done);
                orbWrapper.classList.add("expand");
                loading.classList.add("exiting");
                setTimeout(resolve, 750); // fallback
            });
        }

        async function showApp(userName) {
            welcomeTitle.textContent = userName ? `Lumica Service • ${userName}` : "Lumica Service";
            await runRevealAnimation();
            loading.classList.add("hidden");
            statusCard.classList.add("hidden");
            appContent.classList.remove("hidden");
            mainEl.classList.remove("hidden");
            // плавное появление контента
            requestAnimationFrame(() => {
                mainEl.classList.add("visible");
            });
        }

        function showError(message) {
            loading.classList.add("hidden");
            mainEl.classList.remove("hidden");
            requestAnimationFrame(() => {
                mainEl.classList.add("visible");
            });
            statusTitle.textContent = "Доступ закрыт";
            statusText.textContent = message || "Валидация Telegram initData не прошла, повторите запуск мини‑приложения.";
            appContent.classList.add("hidden");
            statusCard.classList.remove("hidden");
        }

        const DEV_MODE = new URLSearchParams(window.location.search).get("dev") === "1";
        console.log("DEV_MODE", DEV_MODE);

        function fmtDate(iso) {
            if (!iso) return "не задано";
            const d = new Date(iso);
            if (Number.isNaN(d.getTime())) return "не задано";
            return d.toLocaleDateString("ru-RU", { day: "2-digit", month: "long", year: "numeric" });
        }

        function normalizeSubscriptionStatus(status) {
            return String(status || "").trim().toLowerCase();
        }

        function isSubscriptionActive(subscription) {
            const status = normalizeSubscriptionStatus(subscription?.status);
            return status === "active" || status === "lifetime";
        }

        function isSubscriptionLifetime(subscription) {
            return normalizeSubscriptionStatus(subscription?.status) === "lifetime";
        }

        function formatSubscriptionUntil(subscription, formatter = fmtDateTime) {
            if (!subscription) return "\u2014";
            if (isSubscriptionLifetime(subscription)) return "\u0411\u0435\u0441\u0441\u0440\u043e\u0447\u043d\u043e";
            return subscription?.access_until ? formatter(subscription.access_until) : "\u2014";
        }

        function maskTelegramId(raw) {
            if (!raw) return "—";
            const text = String(raw);
            if (text.length <= 4) return text;
            return `••••${text.slice(-4)}`;
        }

        function renderTelegramId() {
            const telegramId = lastUserPayload?.user?.telegram_id;
            if (!telegramId) {
                profileTelegramIdEl.textContent = "—";
                profileIdToggleEl.textContent = "Нет";
                return;
            }
            profileTelegramIdEl.textContent = showFullTelegramId ? String(telegramId) : maskTelegramId(telegramId);
            profileIdToggleEl.textContent = showFullTelegramId ? "Скрыть" : "Показать";
        }

        function fmtConnectionsCount(n) {
            const value = Number(n) || 0;
            const mod10 = value % 10;
            const mod100 = value % 100;
            if (mod10 === 1 && mod100 !== 11) return `${value} подключение`;
            if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return `${value} подключения`;
            return `${value} подключений`;
        }

        function normalizeVlessConnections(payload) {
            const rows = Array.isArray(payload?.connections) ? payload.connections : [];
            if (rows.length) {
                return rows.filter((row) => row?.vless_url);
            }
            if (payload?.ok && payload?.vless_url) {
                return [
                    {
                        label: payload?.identifier || "VLESS",
                        host: payload?.host,
                        port: payload?.port,
                        vless_url: payload?.vless_url,
                        inbound_remark: null,
                    },
                ];
            }
            return [];
        }

        function normalizeMixedConnections(payload) {
            const rows = Array.isArray(payload?.connections) ? payload.connections : [];
            if (rows.length) {
                return rows.filter((row) => Array.isArray(row?.urls) && row.urls.length);
            }
            if (payload?.ok && Array.isArray(payload?.urls) && payload.urls.length) {
                return [
                    {
                        label: payload?.username || "MIXED",
                        host: payload?.host,
                        port: payload?.port,
                        username: payload?.username || null,
                        password: payload?.password || null,
                        urls: payload?.urls,
                        inbound_remark: null,
                    },
                ];
            }
            return [];
        }

        function normalizeHttpConnections(payload) {
            const rows = Array.isArray(payload?.connections) ? payload.connections : [];
            if (rows.length) {
                return rows.filter((row) => Array.isArray(row?.urls) && row.urls.length);
            }
            if (payload?.ok && Array.isArray(payload?.urls) && payload.urls.length) {
                return [
                    {
                        label: payload?.username || "HTTP",
                        host: payload?.host,
                        port: payload?.port,
                        urls: payload?.urls,
                        inbound_remark: null,
                    },
                ];
            }
            return [];
        }

        function connectionProtocolTitle(protocol) {
            if (protocol === "vless") return "VLESS";
            if (protocol === "http") return "HTTP Proxy";
            if (protocol === "mixed") return "Mixed (SOCKS5)";
            return "Подключения";
        }

        function buildConnectionsInfoText(protocol, rows) {
            const safeRows = Array.isArray(rows) ? rows : [];
            const hosts = [...new Set(safeRows.map((r) => String(r?.host || "").trim()).filter(Boolean))];
            const ports = [...new Set(safeRows.map((r) => String(r?.port ?? "").trim()).filter(Boolean))];

            return [
                "Информация о подключениях",
                `Протокол: ${connectionProtocolTitle(protocol)}`,
                `Хост: ${hosts.join(", ") || "—"}`,
                `Порт: ${ports.join(", ") || "—"}`,
            ].join("\n");
        }

        function detectUrlType(url) {
            const raw = String(url || "").trim().toLowerCase();
            if (raw.startsWith("vless://")) return "VLESS";
            if (raw.startsWith("socks5://")) return "SOCKS5";
            if (raw.startsWith("https://")) return "HTTPS";
            if (raw.startsWith("http://")) return "HTTP";
            return "Ссылка";
        }

        function buildTelegramSocksUrl(row) {
            const host = String(row?.host || "").trim();
            const port = String(row?.port ?? "").trim();
            const user = String(row?.username || row?.identifier || "").trim();
            const pass = String(row?.password || "").trim();
            if (!host || !port || !user || !pass) return "";
            return `https://t.me/socks?server=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}&user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}`;
        }

        function openExternalLink(url) {
            const link = String(url || "").trim();
            if (!link) return;
            if (link.startsWith("https://t.me/") && window.Telegram?.WebApp?.openTelegramLink) {
                window.Telegram.WebApp.openTelegramLink(link);
                return;
            }
            if (window.Telegram?.WebApp?.openLink) {
                window.Telegram.WebApp.openLink(link);
                return;
            }
            window.open(link, "_blank", "noopener,noreferrer");
        }

        async function copyToClipboard(value) {
            const text = String(value || "").trim();
            if (!text) throw new Error("empty value");
            if (navigator.clipboard?.writeText) {
                await navigator.clipboard.writeText(text);
                return;
            }
            const ta = document.createElement("textarea");
            ta.value = text;
            ta.setAttribute("readonly", "");
            ta.style.position = "fixed";
            ta.style.left = "-1000px";
            ta.style.top = "-1000px";
            document.body.appendChild(ta);
            ta.select();
            document.execCommand("copy");
            document.body.removeChild(ta);
        }
        const VLESS_SETUP_GUIDE_SHORT = [
            "1. Установи VPN-клиент с поддержкой VLESS (например, Amnezia VPN).",
            "2. Нажми «Копировать VLESS» и вставь ссылку в приложение.",
            "3. Подключись к серверу и проверь доступ к нужным сервисам.",
            "",
            "Совет: включи раздельное туннелирование и оставь VPN только для нужных приложений.",
        ].join("\n");

        function ensureVlessGuideOverlayMounted() {
            if (!vlessGuideOverlayEl) return;
            if (vlessGuideOverlayEl.parentElement !== document.body) {
                document.body.appendChild(vlessGuideOverlayEl);
            }
        }

        async function openVlessGuide() {
            if (!vlessGuideOverlayEl || !vlessGuideTextEl) return;
            if (!vlessGuidePreference.loaded) {
                await loadVlessGuidePreference();
            }
            if (vlessGuidePreference.dontShow) {
                return;
            }
            ensureVlessGuideOverlayMounted();
            applyVlessGuidePreference(vlessGuidePreference.dontShow);
            vlessGuideTextEl.textContent = VLESS_SETUP_GUIDE_SHORT;
            vlessGuideOverlayEl.classList.remove("hidden");
            vlessGuideOverlayEl.setAttribute("aria-hidden", "false");
        }

        function closeVlessGuide() {
            if (!vlessGuideOverlayEl) return;
            vlessGuideOverlayEl.classList.add("hidden");
            vlessGuideOverlayEl.setAttribute("aria-hidden", "true");
        }

        function connectionCopyItems(protocol, row) {
            if (protocol === "vless") {
                return row?.vless_url
                    ? [{ label: "\u041a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c VLESS", value: row.vless_url, action: "copy", showGuide: true }]
                    : [];
            }
            if (protocol === "mixed") {
                const user = String(row?.username || row?.identifier || "").trim();
                const pass = String(row?.password || "").trim();
                const tgSocksUrl = buildTelegramSocksUrl(row);
                const actions = [];
                if (pass) actions.push({ label: "Копировать пароль", value: pass, action: "copy" });
                if (tgSocksUrl) {
                    actions.push({ label: "Добавить в Тг", value: tgSocksUrl, action: "open" });
                }
                return actions;
            }
            const urls = Array.isArray(row?.urls) ? row.urls : [];
            return urls
                .filter(Boolean)
                .map((url) => ({ label: `Копировать ${detectUrlType(url)}`, value: url, action: "copy" }));
        }

        function buildConnectionServerParts(row) {
            const parts = [];
            const panelName = String(row?.panel_name || "").trim();
            const region = String(row?.region || "").trim();
            const memberId = row?.member_id;
            if (panelName) parts.push(panelName);
            if (region) parts.push(region.toUpperCase());
            if (memberId !== null && memberId !== undefined) parts.push(`server#${memberId}`);
            return parts;
        }

        function buildConnectionServerKey(row) {
            return [row?.panel_id, row?.panel_name, row?.region, row?.member_id]
                .map((value) => String(value ?? "").trim().toLowerCase())
                .join("|");
        }

        function groupConnectionsByServer(rows) {
            const groups = [];
            const groupsByKey = new Map();
            rows.forEach((row) => {
                const key = buildConnectionServerKey(row);
                let group = groupsByKey.get(key);
                if (!group) {
                    group = { row, rows: [] };
                    groupsByKey.set(key, group);
                    groups.push(group);
                }
                group.rows.push(row);
            });
            return groups.map((group, index) => {
                const parts = buildConnectionServerParts(group.row);
                const suffix = parts.length ? ` - ${parts.join(" - ")}` : "";
                return {
                    title: `\u0421\u0435\u0440\u0432\u0435\u0440 ${index + 1}${suffix}`,
                    rows: group.rows,
                };
            });
        }

        function openConnectionsMenu() {
            connectionsState.activeProtocol = null;
            connectionsMenuPageEl?.classList.remove("hidden");
            connectionsDetailPageEl?.classList.add("hidden");
            updateConnectionsPageContext(null);
            updateScreenMenuContext("screen-connections");
            updateTelegramBackButton();
        }

        function legacyRenderConnectionsDetail(protocol) {
            if (!connectionsDetailListEl) return;
            const rows = Array.isArray(connectionsState.entries?.[protocol]) ? connectionsState.entries[protocol] : [];
            const title = connectionProtocolTitle(protocol);
            connectionsDetailTitleEl.textContent = title;
            connectionsDetailTitleEl.title = title;
            updateConnectionsPageContext(protocol);
            connectionsDetailSubtitleEl.textContent = buildConnectionsInfoText(protocol, rows);
            connectionsDetailListEl.innerHTML = "";

            if (!rows.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Подключения не найдены.";
                connectionsDetailListEl.appendChild(empty);
                return;
            }

            rows.forEach((row, idx) => {
                const item = document.createElement("div");
                item.className = "connection-item";

                const itemTitle = document.createElement("div");
                itemTitle.className = "connection-item-title";
                const mixedEmail = String(row?.username || row?.identifier || "").trim();
                const rawTitle = String(row?.label || "").trim();
                let displayTitle = rawTitle || `${title} #${idx + 1}`;
                if (protocol === "mixed" && mixedEmail) {
                    const sameAsEmail = displayTitle.toLowerCase() === mixedEmail.toLowerCase();
                    if (sameAsEmail) {
                        displayTitle = `Подключение #${idx + 1}`;
                    }
                }
                itemTitle.textContent = displayTitle;

                if (protocol === "mixed") {
                    const meta = document.createElement("div");
                    meta.className = "connection-item-meta";

                    const emailLine = document.createElement("div");
                    emailLine.textContent = `Почта: ${mixedEmail || "—"}`;

                    meta.appendChild(emailLine);
                    item.appendChild(meta);
                }

                const serverMeta = document.createElement("div");
                serverMeta.className = "connection-item-meta";
                const panelName = String(row?.panel_name || "").trim();
                const region = String(row?.region || "").trim();
                const memberId = row?.member_id;
                const selectedMark = row?.selected ? " • selected" : "";
                const serverParts = [];
                if (panelName) serverParts.push(panelName);
                if (region) serverParts.push(region.toUpperCase());
                if (memberId !== null && memberId !== undefined) serverParts.push(`server#${memberId}`);
                serverMeta.textContent = serverParts.length ? `Сервер: ${serverParts.join(" • ")}${selectedMark}` : `Сервер: —${selectedMark}`;
                item.appendChild(serverMeta);

                const copyRow = document.createElement("div");
                copyRow.className = "connection-copy-row";
                const copies = connectionCopyItems(protocol, row);
                copies.forEach((entry) => {
                    const copyBtn = document.createElement("button");
                    copyBtn.type = "button";
                    copyBtn.className = "connection-copy-btn";
                    copyBtn.textContent = entry.label;
                    copyBtn.addEventListener("click", async () => {
                        const baseText = entry.label;
                        try {
                            if (entry.action === "open") {
                                openExternalLink(entry.value);
                                copyBtn.textContent = "Открыто";
                            } else {
                                await copyToClipboard(entry.value);
                                if (entry.showGuide) {
                                    await openVlessGuide();
                                }
                                copyBtn.textContent = "Скопировано";
                            }
                        } catch (_err) {
                            copyBtn.textContent = "Ошибка";
                        }
                        setTimeout(() => {
                            copyBtn.textContent = baseText;
                        }, 1000);
                    });
                    copyRow.appendChild(copyBtn);
                });

                if (row?.member_id !== null && row?.member_id !== undefined && !row?.selected) {
                    const selectBtn = document.createElement("button");
                    selectBtn.type = "button";
                    selectBtn.className = "connection-copy-btn";
                    selectBtn.textContent = "Выбрать сервер";
                    selectBtn.addEventListener("click", async () => {
                        const original = selectBtn.textContent;
                        try {
                            const groupKey = protocol === "vless" ? "vless" : "socks5";
                            await postJson(vpnSelectServerUrl, { group_key: groupKey, member_id: Number(row.member_id) });
                            const runtime = await loadRuntimeData();
                            renderDashboard(runtime);
                            renderConnectionsDetail(protocol);
                            selectBtn.textContent = "Выбрано";
                        } catch (_err) {
                            selectBtn.textContent = "Ошибка";
                        }
                        setTimeout(() => {
                            selectBtn.textContent = original;
                        }, 1200);
                    });
                    copyRow.appendChild(selectBtn);
                }

                item.appendChild(itemTitle);
                item.appendChild(copyRow);
                connectionsDetailListEl.appendChild(item);
            });
        }

        function renderConnectionsDetail(protocol) {
            if (!connectionsDetailListEl) return;
            const rows = Array.isArray(connectionsState.entries?.[protocol]) ? connectionsState.entries[protocol] : [];
            const title = connectionProtocolTitle(protocol);
            const serverGroups = groupConnectionsByServer(rows);
            connectionsDetailTitleEl.textContent = title;
            connectionsDetailTitleEl.title = title;
            updateConnectionsPageContext(protocol);
            connectionsDetailSubtitleEl.textContent = buildConnectionsInfoText(protocol, rows);
            connectionsDetailListEl.innerHTML = "";

            if (!rows.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Подключения не найдены.";
                connectionsDetailListEl.appendChild(empty);
                return;
            }

            serverGroups.forEach((group) => {
                const groupEl = document.createElement("section");
                groupEl.className = "connection-server-group";

                const groupTitle = document.createElement("div");
                groupTitle.className = "connection-server-header";
                groupTitle.textContent = group.title;
                groupEl.appendChild(groupTitle);

                const groupList = document.createElement("div");
                groupList.className = "connection-server-list";

                group.rows.forEach((row, idx) => {
                    const item = document.createElement("div");
                    item.className = "connection-item";

                    const itemTitle = document.createElement("div");
                    itemTitle.className = "connection-item-title";
                    const mixedEmail = String(row?.username || row?.identifier || "").trim();
                    const rawTitle = String(row?.label || "").trim();
                    let displayTitle = rawTitle || `Подключение ${idx + 1}`;
                    if (protocol === "mixed" && mixedEmail) {
                        const sameAsEmail = displayTitle.toLowerCase() === mixedEmail.toLowerCase();
                        if (sameAsEmail) {
                            displayTitle = `Подключение ${idx + 1}`;
                        }
                    }
                    itemTitle.textContent = displayTitle;
                    item.appendChild(itemTitle);

                    if (protocol === "mixed") {
                        const meta = document.createElement("div");
                        meta.className = "connection-item-meta";

                        const emailLine = document.createElement("div");
                        emailLine.textContent = `Почта: ${mixedEmail || "—"}`;

                        meta.appendChild(emailLine);
                        item.appendChild(meta);
                    }

                    const copyRow = document.createElement("div");
                    copyRow.className = "connection-copy-row";
                    const copies = connectionCopyItems(protocol, row);
                    copies.forEach((entry) => {
                        const copyBtn = document.createElement("button");
                        copyBtn.type = "button";
                        copyBtn.className = "connection-copy-btn";
                        copyBtn.textContent = entry.label;
                        copyBtn.addEventListener("click", async () => {
                            const baseText = entry.label;
                            try {
                                if (entry.action === "open") {
                                    openExternalLink(entry.value);
                                    copyBtn.textContent = "Открыто";
                                } else {
                                    await copyToClipboard(entry.value);
                                    if (entry.showGuide) {
                                        await openVlessGuide();
                                    }
                                    copyBtn.textContent = "Скопировано";
                                }
                            } catch (_err) {
                                copyBtn.textContent = "Ошибка";
                            }
                            setTimeout(() => {
                                copyBtn.textContent = baseText;
                            }, 1000);
                        });
                        copyRow.appendChild(copyBtn);
                    });

                    item.appendChild(copyRow);
                    groupList.appendChild(item);
                });

                groupEl.appendChild(groupList);
                connectionsDetailListEl.appendChild(groupEl);
            });
        }

        function openConnectionsDetail(protocol) {
            if (!connectionsState.visibility?.[protocol]) return;
            const rows = Array.isArray(connectionsState.entries?.[protocol]) ? connectionsState.entries[protocol] : [];
            if (!rows.length) return;
            connectionsState.activeProtocol = protocol;
            renderConnectionsDetail(protocol);
            connectionsMenuPageEl?.classList.add("hidden");
            connectionsDetailPageEl?.classList.remove("hidden");
            updateScreenMenuContext("screen-connections");
            updateTelegramBackButton();
        }

        function renderDashboard(data) {
            const me = data?.me;
            const service = data?.status?.services;
            const subscription = me?.subscription;
            const userStatus = String(me?.user?.status || "verified").toLowerCase();
            isVerifiedUser = userStatus === "verified";
            const subActive = isSubscriptionActive(subscription);
            const lifetimeSub = isSubscriptionLifetime(subscription);
            const subscriptionUntil = formatSubscriptionUntil(subscription, fmtDate);
            const vless = data?.vless;
            const http = data?.http;
            const mixed = data?.mixed;

            applyCloudVisibility(me);
            lastUserPayload = me || null;
            const userRole = me?.user?.role || "user";
            const isOwner = userRole === "owner";
            profileRoleEl.textContent = userRole;
            workRolePillEl.textContent = userRole;
            workOwnerNameEl.textContent = me?.user?.name || me?.user?.first_name || me?.user?.username || "Панель управления";
            workOwnerRoleEl.textContent = userRole;
            navWorkBtn.classList.toggle("hidden", !isOwner);
            bottomNavEl.classList.toggle("with-work", isOwner);
            if (!isOwner) {
                const activeWork = navWorkBtn.classList.contains("active");
                if (activeWork) switchScreen("screen-home");
            } else {
                loadWorkClientsData().catch((err) => {
                    console.error("load clients error:", err);
                });
            }
            renderTelegramId();

            const showVlessCard = isVerifiedUser && service?.vless?.visible_in_app !== false;
            const showHttpCard = isVerifiedUser && service?.http?.visible_in_app === true;
            const showMixedCard =
                isVerifiedUser &&
                (service?.mixed?.visible_in_app === true ||
                    (service?.mixed === undefined && service?.https_mixed?.visible_in_app !== false));
            const vlessConnections = normalizeVlessConnections(vless);
            const httpConnections = normalizeHttpConnections(http);
            const mixedConnections = normalizeMixedConnections(mixed);
            connectionsState.visibility.vless = showVlessCard;
            connectionsState.visibility.http = showHttpCard;
            connectionsState.visibility.mixed = showMixedCard;
            connectionsState.entries.vless = showVlessCard ? vlessConnections : [];
            connectionsState.entries.http = showHttpCard ? httpConnections : [];
            connectionsState.entries.mixed = showMixedCard ? mixedConnections : [];
            vlessCardEl?.classList.toggle("hidden", !showVlessCard);
            httpCardEl?.classList.toggle("hidden", !showHttpCard);
            mixedCardEl?.classList.toggle("hidden", !showMixedCard);
            connectionsHiddenNoteEl?.classList.toggle("hidden", showVlessCard || showHttpCard || showMixedCard);
            if (connectionsState.activeProtocol && !connectionsState.visibility[connectionsState.activeProtocol]) {
                openConnectionsMenu();
            } else if (connectionsState.activeProtocol) {
                renderConnectionsDetail(connectionsState.activeProtocol);
            }

            homeServerSub.textContent = service?.vless?.ok || service?.https_mixed?.ok ? "Сервисы доступны" : "Сервисы недоступны";
            homeServerCardEl?.classList.toggle("hidden", !isVerifiedUser);
            homeConnectionsBtnEl?.classList.toggle("hidden", !isVerifiedUser);
            profileReferralCardEl?.classList.toggle("hidden", isVerifiedUser);
            profileReferralInputCardEl?.classList.toggle("hidden", isVerifiedUser);
            profileReferralStatusCardEl?.classList.toggle("hidden", isVerifiedUser);
            if (!isVerifiedUser) {
                if (!profileReferralStatusEl.textContent || profileReferralStatusEl.textContent === "...") {
                    profileReferralStatusTitleEl.textContent = "Реферальный код";
                    profileReferralStatusEl.textContent = "Введите код, если он у вас есть";
                }
            }
            applyNavSecondButtonConfig();
            if (!isVerifiedUser && getActiveScreenId() === "screen-connections") {
                switchScreen("screen-home");
            }
            if (subActive) {
                homeSubTitle.textContent = "Подписка активна";
                homeSubSub.textContent = "Доступ подтвержден";
                homeSubRight.textContent = lifetimeSub ? "Без срока" : `До: ${subscriptionUntil}`;
                profileSubTitleEl.textContent = "Подписка активна";
                profileSubSubEl.textContent = lifetimeSub ? "Доступ: бессрочно" : `Доступ до: ${subscriptionUntil}`;
                document.getElementById("hero-sub").textContent = lifetimeSub ? "Бессрочная подписка" : `Подписка до ${subscriptionUntil}`;
            } else {
                homeSubTitle.textContent = "Подписка неактивна";
                homeSubSub.textContent = "Оформите/продлите доступ";
                homeSubRight.textContent = "—";
                profileSubTitleEl.textContent = "Подписка неактивна";
                profileSubSubEl.textContent = "Доступ ограничен";
                document.getElementById("hero-sub").textContent = "Требуется активная подписка";
            }

            if (vlessConnections.length) {
                vlessStatusEl.textContent = `Готово • ${fmtConnectionsCount(vlessConnections.length)}`;
                vlessDetailEl.textContent = "›";
            } else {
                vlessStatusEl.textContent = "Не выдано";
                vlessDetailEl.textContent = "—";
            }

            if (httpConnections.length) {
                httpStatusEl.textContent = `Готово • ${fmtConnectionsCount(httpConnections.length)}`;
                httpDetailEl.textContent = "›";
            } else {
                httpStatusEl.textContent = "Не выдано";
                httpDetailEl.textContent = "—";
            }

            if (mixedConnections.length) {
                mixedStatusEl.textContent = `Готово • ${fmtConnectionsCount(mixedConnections.length)}`;
                mixedDetailEl.textContent = "›";
            } else {
                mixedStatusEl.textContent = "Не выдано";
                mixedDetailEl.textContent = "—";
            }
        }

        async function fetchJson(url, optional = false) {
            const response = await fetch(url, {
                method: "GET",
                credentials: "same-origin",
            });
            let payload = {};
            try {
                payload = await response.json();
            } catch (_e) {
                payload = {};
            }
            if (!response.ok || payload?.ok === false) {
                if (optional) return null;
                throw new Error(payload.error || `Ошибка запроса ${url}`);
            }
            return payload;
        }

        function withCsrfHeaders(headers = {}) {
            const merged = { ...headers };
            if (csrfToken) {
                merged["X-CSRF-Token"] = csrfToken;
            }
            return merged;
        }

        async function postJson(url, body = null) {
            const response = await fetch(url, {
                method: "POST",
                credentials: "same-origin",
                headers: withCsrfHeaders({ "Content-Type": "application/json" }),
                body: body ? JSON.stringify(body) : null,
            });
            let payload = {};
            try {
                payload = await response.json();
            } catch (_e) {
                payload = {};
            }
            if (!response.ok || payload?.ok === false) {
                throw new Error(payload.error || `Ошибка запроса ${url}`);
            }
            return payload;
        }

        async function deleteJson(url) {
            const response = await fetch(url, {
                method: "DELETE",
                credentials: "same-origin",
                headers: withCsrfHeaders(),
            });
            let payload = {};
            try {
                payload = await response.json();
            } catch (_e) {
                payload = {};
            }
            if (!response.ok || payload?.ok === false) {
                throw new Error(payload.error || `Ошибка запроса ${url}`);
            }
            return payload;
        }

        function fmtCloudSize(sizeBytes) {
            const value = Number(sizeBytes);
            if (!Number.isFinite(value) || value < 0) return "—";
            if (value < 1024) return `${value} Б`;
            const units = ["КБ", "МБ", "ГБ", "ТБ"];
            let current = value;
            let unitIdx = -1;
            while (current >= 1024 && unitIdx < units.length - 1) {
                current /= 1024;
                unitIdx += 1;
            }
            return `${current.toFixed(current >= 100 ? 0 : 1)} ${units[unitIdx]}`;
        }

        function cloudFileExtension(fileNode) {
            const fileMeta = fileNode?.file || {};
            const extFromMeta = String(fileMeta?.extension || "")
                .trim()
                .toLowerCase()
                .replace(/^\./, "");
            if (extFromMeta) return extFromMeta;

            const rawName = String(fileMeta?.original_name || fileNode?.name || "").trim();
            const dotIndex = rawName.lastIndexOf(".");
            if (dotIndex <= 0 || dotIndex >= rawName.length - 1) return "";
            return rawName.slice(dotIndex + 1).toLowerCase();
        }

        function cloudFileIcon(fileNode) {
            const fileMeta = fileNode?.file || {};
            const mime = String(fileMeta?.mime_type || "").trim().toLowerCase();
            const ext = cloudFileExtension(fileNode);

            if (mime.startsWith("audio/") || cloudAudioExtensions.has(ext)) return "🎵";
            if (mime.startsWith("video/") || cloudVideoExtensions.has(ext)) return "🎬";
            if (mime.startsWith("image/") || cloudImageExtensions.has(ext)) return "🖼️";
            if (
                mime.includes("zip")
                || mime.includes("compressed")
                || mime.includes("archive")
                || mime.includes("x-7z")
                || mime.includes("x-rar")
                || cloudArchiveExtensions.has(ext)
            ) {
                return "🗜️";
            }
            if (mime === "application/pdf" || ext === "pdf") return "📕";
            if (cloudSheetExtensions.has(ext) || mime.includes("spreadsheet") || mime.includes("excel") || mime.includes("csv")) return "📊";
            if (cloudSlideExtensions.has(ext) || mime.includes("presentation") || mime.includes("powerpoint")) return "📽️";
            if (cloudDocumentExtensions.has(ext) || mime.includes("wordprocessingml") || mime.includes("msword")) return "📘";
            if (cloudCodeExtensions.has(ext)) return "💻";
            if (mime.startsWith("text/") || ["txt", "md", "log", "rtf"].includes(ext)) return "📝";
            return "📄";
        }

        function cloudFilePreviewKind(fileNode) {
            const fileMeta = fileNode?.file || {};
            const mime = String(fileMeta?.mime_type || "").trim().toLowerCase();
            const ext = cloudFileExtension(fileNode);
            if (mime.startsWith("video/") || cloudVideoExtensions.has(ext)) return "video";
            if (mime.startsWith("audio/") || cloudAudioExtensions.has(ext)) return "audio";
            return "";
        }

        function cloudInlineFileUrl(fileId) {
            return `${cloudDownloadFileUrl(fileId)}?inline=1`;
        }

        function setCloudPreviewNote(text = "", tone = "info") {
            if (!cloudPreviewNoteEl) return;
            const message = String(text || "").trim();
            cloudPreviewNoteEl.classList.remove("error", "success");
            if (!message) {
                cloudPreviewNoteEl.textContent = "";
                cloudPreviewNoteEl.classList.add("hidden");
                return;
            }
            if (tone === "error" || tone === "success") {
                cloudPreviewNoteEl.classList.add(tone);
            }
            cloudPreviewNoteEl.textContent = message;
            cloudPreviewNoteEl.classList.remove("hidden");
        }

        function clearCloudPreviewMedia() {
            if (!cloudPreviewMediaWrapEl) return;
            const media = cloudPreviewMediaWrapEl.querySelector("audio, video");
            if (media) {
                try {
                    media.pause?.();
                } catch (_e) {
                    // no-op
                }
                media.removeAttribute("src");
                media.load?.();
            }
            cloudPreviewMediaWrapEl.innerHTML = "";
        }

        function closeCloudPreview() {
            if (!cloudPreviewOverlayEl) return;
            clearCloudPreviewMedia();
            setCloudPreviewNote("");
            cloudPreviewOverlayEl.classList.add("hidden");
            cloudPreviewOverlayEl.setAttribute("aria-hidden", "true");
        }

        function openCloudPreview(fileNode) {
            const fileMeta = fileNode?.file || {};
            const previewKind = cloudFilePreviewKind(fileNode);
            const fileId = Number(fileMeta?.file_id || 0);
            if (!previewKind || !fileId) return;

            const fileName = String(fileNode?.name || fileMeta?.original_name || "Медиафайл");
            if (!cloudPreviewOverlayEl || !cloudPreviewMediaWrapEl || !cloudPreviewTitleEl) {
                window.open(cloudInlineFileUrl(fileId), "_blank", "noopener");
                return;
            }

            clearCloudPreviewMedia();
            setCloudPreviewNote("");
            cloudPreviewTitleEl.textContent = fileName;
            cloudPreviewTitleEl.title = fileName;

            const mediaEl = document.createElement(previewKind);
            mediaEl.controls = true;
            mediaEl.autoplay = true;
            mediaEl.preload = "metadata";
            mediaEl.src = cloudInlineFileUrl(fileId);
            mediaEl.className = previewKind === "video" ? "cloud-preview-video" : "cloud-preview-audio";
            if (previewKind === "video") {
                mediaEl.setAttribute("playsinline", "playsinline");
                mediaEl.setAttribute("webkit-playsinline", "webkit-playsinline");
            }
            mediaEl.addEventListener("error", () => {
                setCloudPreviewNote("Не удалось воспроизвести файл. Попробуйте скачать его кнопкой.", "error");
            });

            cloudPreviewMediaWrapEl.appendChild(mediaEl);
            cloudPreviewOverlayEl.classList.remove("hidden");
            cloudPreviewOverlayEl.setAttribute("aria-hidden", "false");
        }

        function setCloudStatus(text = "", tone = "info") {
            if (!cloudStatusNoteEl) return;
            const message = String(text || "").trim();
            cloudStatusNoteEl.classList.remove("error", "success");
            if (!message) {
                cloudStatusNoteEl.textContent = "";
                cloudStatusNoteEl.classList.add("hidden");
                return;
            }
            if (tone === "error" || tone === "success") {
                cloudStatusNoteEl.classList.add(tone);
            }
            cloudStatusNoteEl.textContent = message;
            cloudStatusNoteEl.classList.remove("hidden");
        }

        function setCloudUploadProgress(percent, text = "") {
            const safePercent = Math.max(0, Math.min(100, Number(percent) || 0));
            if (cloudUploadProgressBarEl) {
                cloudUploadProgressBarEl.style.width = `${safePercent}%`;
            }
            if (cloudUploadProgressEl) {
                cloudUploadProgressEl.classList.remove("hidden");
                cloudUploadProgressEl.setAttribute("aria-valuenow", String(Math.round(safePercent)));
            }
            if (cloudUploadProgressTextEl) {
                cloudUploadProgressTextEl.textContent = text || `${Math.round(safePercent)}%`;
                cloudUploadProgressTextEl.classList.remove("hidden");
            }
        }

        function resetCloudUploadProgress(hide = true) {
            if (cloudUploadProgressBarEl) {
                cloudUploadProgressBarEl.style.width = "0%";
            }
            if (cloudUploadProgressEl) {
                cloudUploadProgressEl.setAttribute("aria-valuenow", "0");
                if (hide) {
                    cloudUploadProgressEl.classList.add("hidden");
                }
            }
            if (cloudUploadProgressTextEl) {
                cloudUploadProgressTextEl.textContent = "0%";
                if (hide) {
                    cloudUploadProgressTextEl.classList.add("hidden");
                }
            }
        }

        async function uploadSingleCloudFile(file, targetPath, onProgress) {
            return new Promise((resolve, reject) => {
                const xhr = new XMLHttpRequest();
                xhr.open("POST", cloudUploadUrl, true);
                xhr.withCredentials = true;
                xhr.timeout = 0;
                if (csrfToken) {
                    xhr.setRequestHeader("X-CSRF-Token", csrfToken);
                }

                xhr.upload.onprogress = (event) => {
                    if (!onProgress) return;
                    const total = event.lengthComputable ? Number(event.total) : Number(file?.size || 0);
                    onProgress(Number(event.loaded || 0), total);
                };

                xhr.onerror = () => {
                    reject(new Error("Сетевая ошибка при загрузке"));
                };
                xhr.ontimeout = () => {
                    reject(new Error("Таймаут загрузки файла"));
                };
                xhr.onabort = () => {
                    reject(new Error("Загрузка отменена"));
                };
                xhr.onload = () => {
                    let payload = {};
                    try {
                        payload = JSON.parse(xhr.responseText || "{}");
                    } catch (_e) {
                        payload = {};
                    }
                    if (xhr.status >= 200 && xhr.status < 300 && payload?.ok !== false) {
                        resolve(payload);
                        return;
                    }

                    const rawText = String(xhr.responseText || "").trim();
                    const serverError = String(payload?.error || "").trim();
                    const looksLikeHtml = /^<!doctype|^<html/i.test(rawText);
                    const fallbackByStatus =
                        xhr.status === 413
                            ? "Файл слишком большой для nginx (лимит client_max_body_size)"
                            : xhr.status === 504
                                ? "Nginx не дождался ответа бэкенда (увеличьте proxy_read_timeout/proxy_send_timeout)"
                                : xhr.status === 502
                                    ? "Ошибка шлюза между nginx и бэкендом/Telegram"
                            : xhr.statusText || `HTTP ${xhr.status}`;
                    const detail =
                        serverError
                        || (xhr.status === 413
                            ? fallbackByStatus
                            : (!looksLikeHtml && rawText ? rawText : fallbackByStatus));
                    reject(new Error(`${detail} (HTTP ${xhr.status})`));
                };

                const formData = new FormData();
                formData.append("path", targetPath);
                formData.append("file", file, file.name);
                xhr.send(formData);
            });
        }

        function renderCloudList() {
            if (!cloudListEl) return;
            cloudListEl.innerHTML = "";
            const folders = Array.isArray(cloudState.folders) ? cloudState.folders : [];
            const files = Array.isArray(cloudState.files) ? cloudState.files : [];

            if (!folders.length && !files.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Папка пуста. Загрузите файл или создайте папку.";
                cloudListEl.appendChild(empty);
                return;
            }

            folders.forEach((folder) => {
                const row = document.createElement("div");
                row.className = "cloud-node-card";

                const head = document.createElement("div");
                head.className = "cloud-node-head";

                const openBtn = document.createElement("button");
                openBtn.type = "button";
                openBtn.className = "cloud-node-open";
                openBtn.textContent = `📁 ${folder.name || "Папка"}`;
                openBtn.addEventListener("click", () => {
                    loadCloudPath(folder.path || "/").catch((err) => {
                        console.error("open folder error:", err);
                        setCloudStatus(err.message || "Не удалось открыть папку", "error");
                    });
                });

                const actions = document.createElement("div");
                actions.className = "cloud-node-actions";

                const deleteBtn = document.createElement("button");
                deleteBtn.type = "button";
                deleteBtn.className = "cloud-node-action danger";
                deleteBtn.textContent = "Удалить";
                deleteBtn.addEventListener("click", async () => {
                    if (!window.confirm(`Удалить папку "${folder.name}"?`)) return;
                    try {
                        await deleteJson(cloudDeleteNodeUrl(folder.node_id));
                        await loadCloudPath(cloudState.path);
                        setCloudStatus(`Папка "${folder.name}" удалена`, "success");
                    } catch (err) {
                        console.error("delete folder error:", err);
                        setCloudStatus(err.message || "Не удалось удалить папку", "error");
                    }
                });

                actions.appendChild(deleteBtn);
                head.appendChild(openBtn);
                head.appendChild(actions);

                const sub = document.createElement("div");
                sub.className = "cloud-node-sub";
                sub.textContent = "Папка";

                row.appendChild(head);
                row.appendChild(sub);
                cloudListEl.appendChild(row);
            });

            files.forEach((fileNode) => {
                const fileMeta = fileNode?.file || {};
                const isReady = String(fileMeta?.status || "").toLowerCase() === "ready";
                const previewKind = cloudFilePreviewKind(fileNode);
                const canPreview = Boolean(previewKind && isReady && fileMeta?.file_id);

                const row = document.createElement("div");
                row.className = "cloud-node-card";

                const head = document.createElement("div");
                head.className = "cloud-node-head";

                const title = document.createElement(canPreview ? "button" : "div");
                if (canPreview) {
                    title.type = "button";
                }
                title.className = `cloud-node-open${canPreview ? " previewable" : ""}`;
                title.textContent = `${cloudFileIcon(fileNode)} ${fileNode?.name || "Файл"}`;
                if (canPreview) {
                    title.title = previewKind === "video" ? "Открыть видео" : "Открыть аудио";
                    title.addEventListener("click", () => {
                        openCloudPreview(fileNode);
                    });
                } else {
                    title.style.cursor = "default";
                }

                const actions = document.createElement("div");
                actions.className = "cloud-node-actions";

                const downloadBtn = document.createElement("button");
                downloadBtn.type = "button";
                downloadBtn.className = "cloud-node-action";
                downloadBtn.textContent = "Скачать";
                downloadBtn.disabled = !isReady || !fileMeta?.file_id;
                downloadBtn.addEventListener("click", () => {
                    if (!fileMeta?.file_id || !isReady) return;
                    const a = document.createElement("a");
                    a.href = cloudDownloadFileUrl(fileMeta.file_id);
                    a.download = String(fileMeta.original_name || fileNode?.name || "download.bin");
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    setCloudStatus(`Скачивание: ${fileNode?.name || "файл"}`, "success");
                });

                const deleteBtn = document.createElement("button");
                deleteBtn.type = "button";
                deleteBtn.className = "cloud-node-action danger";
                deleteBtn.textContent = "Удалить";
                deleteBtn.addEventListener("click", async () => {
                    if (!window.confirm(`Удалить файл "${fileNode?.name}"?`)) return;
                    try {
                        await deleteJson(cloudDeleteNodeUrl(fileNode.node_id));
                        await loadCloudPath(cloudState.path);
                        setCloudStatus(`Файл "${fileNode?.name}" удален`, "success");
                    } catch (err) {
                        console.error("delete file error:", err);
                        setCloudStatus(err.message || "Не удалось удалить файл", "error");
                    }
                });

                actions.appendChild(downloadBtn);
                actions.appendChild(deleteBtn);
                head.appendChild(title);
                head.appendChild(actions);

                const sizeText = fmtCloudSize(fileMeta?.size_bytes);
                const chunksText = Number(fileMeta?.chunk_count) > 0 ? `${fileMeta.chunk_count} чанк(ов)` : "0 чанков";
                const statusText = fileMeta?.status || "unknown";
                const sub = document.createElement("div");
                sub.className = "cloud-node-sub";
                sub.textContent = `${sizeText} • ${chunksText} • ${statusText}`;

                row.appendChild(head);
                row.appendChild(sub);
                cloudListEl.appendChild(row);
            });
        }

        async function loadCloudPath(path, options = {}) {
            const preserveStatus = Boolean(options?.preserveStatus);
            const nextPath = normalizeCloudPath(path || "/");
            cloudState.path = nextPath;
            if (cloudPathEl) {
                cloudPathEl.textContent = nextPath;
                cloudPathEl.title = nextPath;
            }
            updateCloudPageContext(nextPath);
            updateCloudUpButton();
            updateTelegramBackButton();

            if (cloudListEl) {
                cloudListEl.innerHTML = '<div class="work-empty">Загрузка...</div>';
            }
            try {
                const payload = await fetchJson(`${cloudListUrl}?path=${encodeURIComponent(nextPath)}`, false);
                cloudState.folders = Array.isArray(payload?.folders) ? payload.folders : [];
                cloudState.files = Array.isArray(payload?.files) ? payload.files : [];
                cloudState.path = normalizeCloudPath(payload?.path || nextPath);
                if (cloudPathEl) {
                    cloudPathEl.textContent = cloudState.path;
                    cloudPathEl.title = cloudState.path;
                }
                updateCloudPageContext(cloudState.path);
                cloudState.initialized = true;
                renderCloudList();
                if (!preserveStatus) {
                    setCloudStatus("");
                }
            } catch (err) {
                const message = String(err?.message || "Не удалось загрузить облако");
                if (nextPath !== "/" && message.toLowerCase().includes("folder not found")) {
                    return loadCloudPath(cloudParentPath(nextPath), options);
                }
                cloudState.folders = [];
                cloudState.files = [];
                if (cloudListEl) {
                    cloudListEl.innerHTML = '<div class="work-empty">Не удалось загрузить содержимое облака.</div>';
                }
                setCloudStatus(message, "error");
                throw err;
            } finally {
                updateCloudUpButton();
                updateTelegramBackButton();
            }
        }

        async function ensureCloudLoaded(force = false) {
            updateCloudPageContext(cloudState.path);
            if (!force && cloudState.initialized) {
                updateCloudUpButton();
                return;
            }
            await loadCloudPath(cloudState.path);
        }

        async function createCloudFolder() {
            const rawName = window.prompt("Введите имя папки");
            if (rawName === null) return;
            const name = String(rawName).trim();
            if (!name) {
                setCloudStatus("Имя папки не может быть пустым", "error");
                return;
            }
            try {
                const result = await postJson(cloudMkdirUrl, {
                    parent_path: cloudState.path,
                    name,
                });
                await loadCloudPath(cloudState.path);
                setCloudStatus(
                    result?.existing ? `Папка "${name}" уже существует` : `Папка "${name}" создана`,
                    result?.existing ? "info" : "success"
                );
            } catch (err) {
                console.error("mkdir error:", err);
                setCloudStatus(err.message || "Не удалось создать папку", "error");
            }
        }

        async function uploadCloudFiles(fileList) {
            const files = Array.from(fileList || []);
            if (!files.length || cloudState.isUploading) return;

            cloudState.isUploading = true;
            cloudUploadInputEl && (cloudUploadInputEl.disabled = true);
            cloudUploadLabelEl?.classList.add("disabled");
            cloudNewFolderBtnEl && (cloudNewFolderBtnEl.disabled = true);
            cloudUpBtnEl && (cloudUpBtnEl.disabled = true);

            let uploaded = 0;
            let failed = 0;
            const uploadErrors = [];
            const totalBytes = files.reduce((sum, file) => sum + Math.max(0, Number(file?.size) || 0), 0);
            const totalFiles = files.length;
            let processedBytes = 0;
            resetCloudUploadProgress(false);
            setCloudUploadProgress(0, "Загрузка: 0%");

            try {
                for (const file of files) {
                    const fileSize = Math.max(0, Number(file?.size) || 0);
                    setCloudStatus(`Загрузка: ${file.name}`);
                    try {
                        await uploadSingleCloudFile(file, cloudState.path, (loaded, total) => {
                            const effectiveTotal = total > 0 ? total : fileSize;
                            let percent = 0;
                            if (totalBytes > 0) {
                                const safeLoaded = Math.max(0, Math.min(Number(loaded || 0), effectiveTotal || Number(loaded || 0)));
                                const overallLoaded = Math.min(processedBytes + safeLoaded, totalBytes);
                                percent = (overallLoaded / totalBytes) * 100;
                            } else {
                                const perFileProgress = effectiveTotal > 0 ? Math.min(Number(loaded || 0) / effectiveTotal, 1) : 0;
                                percent = ((uploaded + perFileProgress) / totalFiles) * 100;
                            }
                            setCloudUploadProgress(percent, `Загрузка: ${Math.round(percent)}%`);
                        });
                        uploaded += 1;
                    } catch (err) {
                        failed += 1;
                        console.error("upload error:", err);
                        const reason = String(err?.message || "upload failed").trim();
                        uploadErrors.push({
                            fileName: file.name,
                            reason,
                        });
                    } finally {
                        processedBytes += fileSize;
                        const processedFiles = uploaded + failed;
                        const percent =
                            totalBytes > 0
                                ? (processedBytes / totalBytes) * 100
                                : (processedFiles / totalFiles) * 100;
                        setCloudUploadProgress(percent, `Загрузка: ${Math.round(percent)}%`);
                    }
                }

                await loadCloudPath(cloudState.path, { preserveStatus: true });
                if (failed === 0) {
                    setCloudUploadProgress(100, "Загрузка: 100%");
                    setCloudStatus(`Загружено файлов: ${uploaded}`, "success");
                    setTimeout(() => {
                        if (!cloudState.isUploading) {
                            resetCloudUploadProgress(true);
                        }
                    }, 1200);
                    return;
                }

                const firstError = uploadErrors[0];
                if (uploaded === 0 && failed === 1 && firstError) {
                    setCloudStatus(`Ошибка загрузки "${firstError.fileName}": ${firstError.reason}`, "error");
                    return;
                }

                const summary = `Загружено: ${uploaded}, ошибок: ${failed}`;
                if (firstError) {
                    const prefix = failed > 1 ? "Первая ошибка" : "Ошибка";
                    setCloudStatus(`${summary}. ${prefix}: "${firstError.fileName}" — ${firstError.reason}`, "error");
                    return;
                }
                setCloudStatus(summary, "error");
            } finally {
                cloudState.isUploading = false;
                cloudUploadInputEl && (cloudUploadInputEl.disabled = false);
                cloudUploadLabelEl?.classList.remove("disabled");
                cloudNewFolderBtnEl && (cloudNewFolderBtnEl.disabled = false);
                cloudUpBtnEl && (cloudUpBtnEl.disabled = false);
            }
        }

        function fillSelect(el, items, mapLabel, mapValue, emptyText) {
            if (!el) return;
            el.innerHTML = "";
            const empty = document.createElement("option");
            empty.value = "";
            empty.textContent = emptyText;
            el.appendChild(empty);
            items.forEach((item, idx) => {
                const opt = document.createElement("option");
                opt.value = mapValue(item, idx);
                opt.textContent = mapLabel(item, idx);
                el.appendChild(opt);
            });
        }

        function inboundOptionLabel(inbound) {
            const panelState = inbound?.enable ? "panel:on" : "panel:off";
            const appState = inbound?.show_in_app ? "app:visible" : "app:hidden";
            const panelName = String(inbound?.panel_name || "").trim();
            const region = String(inbound?.region || "").trim();
            const panelPrefix = panelName ? `${panelName}${region ? ` (${region})` : ""} • ` : "";
            return `${panelPrefix}${inbound.panel_inbound_id} • ${inbound.protocol || "unknown"} • ${inbound.remark || "no-remark"} • ${panelState} • ${appState}`;
        }

        function renderWorkInboundSelectOptions() {
            if (!workInboundSelectEl) return;
            const selected = workInboundSelectEl.value;
            fillSelect(
                workInboundSelectEl,
                workState.inbounds,
                (i) => inboundOptionLabel(i),
                (i) => String(i.panel_inbound_ref_id),
                "Выбери inbound"
            );
            if (selected && workState.inbounds.some((i) => String(i.panel_inbound_ref_id) === selected)) {
                workInboundSelectEl.value = selected;
            }
        }

        function renderWorkPendingInboundSelectOptions() {
            if (!workPendingInboundSelectEl) return;
            const selected = workPendingInboundSelectEl.value;
            fillSelect(
                workPendingInboundSelectEl,
                workState.inbounds,
                (i) => inboundOptionLabel(i),
                (i) => String(i.panel_inbound_ref_id),
                "Выбери inbound"
            );
            if (selected && workState.inbounds.some((i) => String(i.panel_inbound_ref_id) === selected)) {
                workPendingInboundSelectEl.value = selected;
            }
        }

        function fmtDateTime(iso) {
            if (!iso) return "—";
            const d = new Date(iso);
            if (Number.isNaN(d.getTime())) return "—";
            return d.toLocaleString("ru-RU", {
                day: "2-digit",
                month: "2-digit",
                year: "numeric",
                hour: "2-digit",
                minute: "2-digit",
            });
        }

        function fmtMoney(value) {
            if (value === null || value === undefined || value === "") return "—";
            const n = Number(value);
            if (Number.isNaN(n)) return "—";
            return `${n.toLocaleString("ru-RU")} ₽`;
        }

        function fmtMonthsText(months) {
            const m = Number(months) || 0;
            if (m % 10 === 1 && m % 100 !== 11) return `${m} месяц`;
            if (m % 10 >= 2 && m % 10 <= 4 && (m % 100 < 10 || m % 100 >= 20)) return `${m} месяца`;
            return `${m} месяцев`;
        }

        function toInputDateValue(dateObj) {
            if (!(dateObj instanceof Date) || Number.isNaN(dateObj.getTime())) return "";
            const year = dateObj.getFullYear();
            const month = String(dateObj.getMonth() + 1).padStart(2, "0");
            const day = String(dateObj.getDate()).padStart(2, "0");
            return `${year}-${month}-${day}`;
        }

        function defaultSubscriptionDateValue(days = 30) {
            const target = new Date();
            target.setHours(0, 0, 0, 0);
            target.setDate(target.getDate() + Math.max(1, Number(days) || 30));
            return toInputDateValue(target);
        }

        function validateSubscriptionDateValue(rawDate) {
            const clean = String(rawDate || "").trim();
            if (!clean) {
                throw new Error("Укажи дату окончания подписки");
            }
            const ts = Date.parse(`${clean}T00:00:00`);
            if (Number.isNaN(ts)) {
                throw new Error("Неверный формат даты");
            }
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            if (ts < today.getTime()) {
                throw new Error("Дата окончания не может быть в прошлом");
            }
            return `${clean}T23:59:59`;
        }

        function renderWorkSubscriptionControls(sub) {
            const hasSubscription = Boolean(sub);
            const lifetimeSubscription = isSubscriptionLifetime(sub);
            const selectedStatus = normalizeSubscriptionStatus(workSubStatusSelectEl?.value || sub?.status || "active");
            const createAsLifetime = !hasSubscription && selectedStatus === "lifetime";
            const switchingLifetimeToActive = hasSubscription && lifetimeSubscription && selectedStatus === "active";
            workSubExtendWrapEl?.classList.toggle(
                "hidden",
                !hasSubscription || lifetimeSubscription || switchingLifetimeToActive
            );
            workSubCreateWrapEl?.classList.toggle(
                "hidden",
                (hasSubscription && !switchingLifetimeToActive) || createAsLifetime
            );

            if (workSubExtendBtnEl) {
                if (!hasSubscription && createAsLifetime) {
                    workSubExtendBtnEl.textContent = "Создать бессрочную подписку";
                } else {
                    workSubExtendBtnEl.textContent = hasSubscription
                        ? "Продлить подписку"
                        : "Создать подписку";
                }
                workSubExtendBtnEl.classList.toggle(
                    "hidden",
                    (hasSubscription && lifetimeSubscription) || switchingLifetimeToActive
                );
            }

            if (workSubCreateDateEl) {
                if ((!hasSubscription && !createAsLifetime) || switchingLifetimeToActive) {
                    if (!workSubCreateDateEl.value) {
                        workSubCreateDateEl.value = defaultSubscriptionDateValue(30);
                    }
                }
                if (createAsLifetime) {
                    workSubCreateDateEl.value = "";
                }
                if (hasSubscription && !lifetimeSubscription && sub?.access_until) {
                    const accessUntil = new Date(sub.access_until);
                    if (!Number.isNaN(accessUntil.getTime())) {
                        workSubCreateDateEl.value = toInputDateValue(accessUntil);
                    }
                }
            }
        }
        function isValidTelegramId(rawValue) {
            return /^\d+$/.test(String(rawValue || "").trim());
        }

        function setPendingSubscriptionStatus(message, tone = "") {
            if (!workPendingSubSaveStatusEl) return;
            workPendingSubSaveStatusEl.classList.remove("success", "error");
            if (!message) {
                workPendingSubSaveStatusEl.textContent = "";
                workPendingSubSaveStatusEl.classList.add("hidden");
                return;
            }
            if (tone === "success" || tone === "error") {
                workPendingSubSaveStatusEl.classList.add(tone);
            }
            workPendingSubSaveStatusEl.textContent = message;
            workPendingSubSaveStatusEl.classList.remove("hidden");
        }

        function upsertWorkUserFromOverview(overview) {
            const user = overview?.user || null;
            if (!user?.id) return;
            const normalized = {
                id: user.id,
                telegram_id: user.telegram_id,
                username: user.username,
                name: user.name,
                role: user.role,
            };
            const idx = workState.users.findIndex((row) => String(row?.id) === String(user.id));
            if (idx >= 0) {
                workState.users[idx] = { ...workState.users[idx], ...normalized };
            } else {
                workState.users.push(normalized);
                workState.users.sort((a, b) => Number(a?.id || 0) - Number(b?.id || 0));
            }
            renderWorkClientCards();
        }

        function renderPendingSubscriptionControls(sub, options = {}) {
            const preserveDate = Boolean(options?.preserveDate);
            const selectedStatus = normalizeSubscriptionStatus(workPendingSubStatusSelectEl?.value || "active");
            const lifetimeSelected = selectedStatus === "lifetime";

            workPendingSubCreateWrapEl?.classList.toggle("hidden", lifetimeSelected);
            if (workPendingSubSaveBtnEl) {
                if (lifetimeSelected) {
                    workPendingSubSaveBtnEl.textContent = sub ? "Сохранить бессрочную подписку" : "Создать бессрочную подписку";
                } else {
                    workPendingSubSaveBtnEl.textContent = sub ? "Сохранить подписку" : "Создать подписку";
                }
            }

            if (!workPendingSubCreateDateEl) {
                return;
            }
            if (lifetimeSelected) {
                workPendingSubCreateDateEl.value = "";
                return;
            }
            if (preserveDate) {
                if (!workPendingSubCreateDateEl.value) {
                    workPendingSubCreateDateEl.value = defaultSubscriptionDateValue(30);
                }
                return;
            }
            if (sub?.access_until) {
                const accessUntil = new Date(sub.access_until);
                if (!Number.isNaN(accessUntil.getTime())) {
                    workPendingSubCreateDateEl.value = toInputDateValue(accessUntil);
                    return;
                }
            }
            workPendingSubCreateDateEl.value = defaultSubscriptionDateValue(30);
        }

        function renderPendingSubscriptionOverview(overview) {
            workState.pendingOverview = overview || null;
            const sub = overview?.subscription || null;
            const conn = overview?.connections || null;

            if (workPendingSubStatusSelectEl) {
                workPendingSubStatusSelectEl.value = sub?.status || "active";
            }
            if (workPendingSubPriceInputEl) {
                workPendingSubPriceInputEl.value = sub?.price_amount ?? "";
            }
            if (workPendingSubLimitInputEl) {
                workPendingSubLimitInputEl.value =
                    conn?.limit === null || conn?.limit === undefined ? "" : String(conn.limit);
            }
            renderPendingSubscriptionControls(sub);
        }

        async function loadPendingSubscriptionOverview(telegramIdRaw) {
            const telegramId = String(telegramIdRaw || "").trim();
            if (!telegramId) {
                renderPendingSubscriptionOverview(null);
                setPendingSubscriptionStatus("Укажи Telegram ID и сохрани параметры подписки.");
                return { ok: true, exists: false, overview: null };
            }
            if (!isValidTelegramId(telegramId)) {
                renderPendingSubscriptionOverview(null);
                setPendingSubscriptionStatus("Telegram ID должен содержать только цифры.", "error");
                return { ok: false, exists: false, overview: null };
            }

            const resp = await fetchJson(adminUserOverviewByTelegramUrl(telegramId), false);
            renderPendingSubscriptionOverview(resp?.overview || null);
            if (resp?.exists) {
                upsertWorkUserFromOverview(resp?.overview || null);
                const userId = resp?.overview?.user?.id;
                setPendingSubscriptionStatus(
                    userId ? `Пользователь #${userId} найден. Можно обновить подписку.` : "Пользователь найден."
                );
            } else {
                setPendingSubscriptionStatus("Пользователь будет создан автоматически при сохранении подписки.");
            }
            return resp;
        }

        function renderWorkSubExtendValue() {
            if (!workSubExtendRangeEl || !workSubExtendValueEl) return;
            const min = Number(workSubExtendRangeEl.min || 0);
            const max = Number(workSubExtendRangeEl.max || 100);
            const value = Number(workSubExtendRangeEl.value || min);
            const percent = max > min ? ((value - min) / (max - min)) * 100 : 0;
            workSubExtendRangeEl.style.setProperty("--work-sub-progress", `${percent}%`);
            workSubExtendValueEl.textContent = fmtMonthsText(value);
        }

        function renderWorkClientCards() {
            if (!workClientCardsEl) return;
            workClientCardsEl.innerHTML = "";

            if (!Array.isArray(workState.users) || !workState.users.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Клиенты не найдены.";
                workClientCardsEl.appendChild(empty);
                return;
            }

            const query = String(workClientSearchEl?.value || "").trim().toLowerCase();
            const filtered = query
                ? workState.users.filter((user) => {
                    const name = String(user?.name || "").toLowerCase();
                    const username = String(user?.username || "").toLowerCase();
                    const telegramId = String(user?.telegram_id || "").toLowerCase();
                    const id = String(user?.id || "").toLowerCase();
                    return [name, username, telegramId, id].some((value) => value.includes(query));
                })
                : workState.users;

            if (!filtered.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Ничего не найдено.";
                workClientCardsEl.appendChild(empty);
                return;
            }

            filtered.forEach((user) => {
                const card = document.createElement("button");
                card.type = "button";
                card.className = "work-client-card";
                card.dataset.userId = String(user.id);

                const title = document.createElement("div");
                title.className = "work-client-card-title";
                title.textContent = user.name || user.username || `Клиент #${user.id}`;

                const sub = document.createElement("div");
                sub.className = "work-client-card-sub";
                sub.textContent = `${user.id} · ${user.username ? `@${user.username}` : "—"}`;

                card.appendChild(title);
                card.appendChild(sub);
                card.addEventListener("click", () => {
                    openWorkClientPage(user.id).catch((err) => {
                        console.error("open client error:", err);
                    });
                });
                workClientCardsEl.appendChild(card);
            });
        }

        function createWorkInboundStatusBadge(kind, enabled, mode = "icon") {
            const isOn = Boolean(enabled);
            const badge = document.createElement("span");
            const isTextMode = mode === "text";
            if (kind === "panel") {
                badge.className = `work-inbound-pill ${isOn ? "panel-on" : "panel-off"}${isTextMode ? " text" : ""}`;
                badge.textContent = isTextMode ? (isOn ? "Панель: on" : "Панель: off") : "🖥️";
                badge.title = isOn ? "Панель: on" : "Панель: off";
            } else {
                badge.className = `work-inbound-pill ${isOn ? "visibility-on" : "visibility-off"}${isTextMode ? " text" : ""}`;
                badge.textContent = isTextMode ? (isOn ? "В приложении: видно" : "В приложении: скрыто") : "👁️";
                badge.title = isOn ? "В приложении: видно" : "В приложении: скрыто";
            }
            badge.setAttribute("aria-label", badge.title);
            return badge;
        }

        function setInboundDetailAddStatus(message, tone = "") {
            if (!workInboundDetailAddStatusEl) return;
            workInboundDetailAddStatusEl.classList.remove("success", "error");
            if (!message) {
                workInboundDetailAddStatusEl.textContent = "";
                workInboundDetailAddStatusEl.classList.add("hidden");
                return;
            }
            if (tone === "success" || tone === "error") {
                workInboundDetailAddStatusEl.classList.add(tone);
            }
            workInboundDetailAddStatusEl.textContent = message;
            workInboundDetailAddStatusEl.classList.remove("hidden");
        }

        function renderWorkInboundDetailClients(clients, emptyMessage = "Клиенты не найдены.") {
            if (!workInboundDetailClientsListEl) return;
            workInboundDetailClientsListEl.innerHTML = "";

            const rows = Array.isArray(clients) ? clients : [];
            if (!rows.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = emptyMessage;
                workInboundDetailClientsListEl.appendChild(empty);
                return;
            }

            rows.forEach((client, index) => {
                const item = document.createElement("div");
                item.className = "work-inbound-client-row";

                const title = document.createElement("div");
                title.className = "work-inbound-client-title";
                const clientLabel = String(client?.label || "").trim() || String(client?.identifier || "").trim() || `Client ${index + 1}`;
                title.textContent = `${index + 1}. ${clientLabel}`;
                title.title = clientLabel;

                const meta = document.createElement("div");
                meta.className = "work-inbound-client-meta";
                const parts = [];
                if (client?.identifier) {
                    parts.push(`id: ${client.identifier}`);
                }
                if (client?.sub_id) {
                    parts.push(`sub: ${client.sub_id}`);
                }
                meta.textContent = parts.length ? parts.join(" • ") : "Без доп. данных";

                item.appendChild(title);
                item.appendChild(meta);
                workInboundDetailClientsListEl.appendChild(item);
            });
        }

        async function loadWorkInboundDetailClients(panelInboundRefIdRaw) {
            const panelInboundRefId = Number(panelInboundRefIdRaw || 0);
            if (!panelInboundRefId) {
                renderWorkInboundDetailClients([], "Выбери подключение в списке.");
                return [];
            }

            const resp = await fetchJson(adminInboundClientsUrl(panelInboundRefId), false);
            const clients = Array.isArray(resp?.clients) ? resp.clients : [];
            renderWorkInboundDetailClients(clients);
            return clients;
        }

        function clearWorkInboundDetail(note = "Выбери подключение в списке.") {
            workState.selectedInboundPanelId = null;

            if (workInboundDetailTitleEl) {
                workInboundDetailTitleEl.textContent = "Подключение";
                workInboundDetailTitleEl.title = "Подключение";
            }
            if (workInboundDetailMetaEl) {
                workInboundDetailMetaEl.textContent = "—";
            }
            if (workInboundDetailBadgesEl) {
                workInboundDetailBadgesEl.innerHTML = "";
            }
            if (workInboundDetailToggleBtnEl) {
                workInboundDetailToggleBtnEl.textContent = "Скрыть у пользователей";
                workInboundDetailToggleBtnEl.disabled = true;
                workInboundDetailToggleBtnEl.removeAttribute("data-panel-inbound-id");
                workInboundDetailToggleBtnEl.removeAttribute("data-next-visible");
            }
            if (workInboundDetailNoteEl) {
                workInboundDetailNoteEl.textContent = note;
            }
            if (workInboundDetailNewClientLabelEl) {
                workInboundDetailNewClientLabelEl.value = "";
            }
            setInboundDetailAddStatus("");
            renderWorkInboundDetailClients([], "Клиенты еще не загружены.");
        }

        function renderWorkInboundDetail(panelInboundRefIdRaw) {
            const panelInboundRefId = Number(panelInboundRefIdRaw || 0);
            if (!panelInboundRefId) {
                clearWorkInboundDetail();
                return;
            }

            const inbound = workState.inbounds.find((row) => String(row?.panel_inbound_ref_id) === String(panelInboundRefId));
            if (!inbound) {
                clearWorkInboundDetail(`Подключение #${panelInboundRefId} не найдено.`);
                return;
            }
            workState.selectedInboundPanelId = panelInboundRefId;

            const panelEnabled = Boolean(inbound?.enable);
            const visibleForUsers = Boolean(inbound?.show_in_app);
            const titleText = String(inbound?.remark || `Inbound ${panelInboundRefId}`).trim() || `Inbound ${panelInboundRefId}`;
            const protocol = String(inbound?.protocol || "unknown").toLowerCase();
            const externalInboundId = inbound?.panel_inbound_id ?? "—";
            const panelName = String(inbound?.panel_name || "").trim() || "—";
            const region = String(inbound?.region || "").trim();
            const panelLabel = `${panelName}${region ? ` (${region})` : ""}`;

            if (workInboundDetailTitleEl) {
                workInboundDetailTitleEl.textContent = titleText;
                workInboundDetailTitleEl.title = titleText;
            }
            if (workInboundDetailMetaEl) {
                workInboundDetailMetaEl.textContent = `Панель: ${panelLabel} • #${externalInboundId} • ${protocol} • порт: ${inbound?.port ?? "—"}`;
            }
            if (workInboundDetailBadgesEl) {
                workInboundDetailBadgesEl.innerHTML = "";
                workInboundDetailBadgesEl.appendChild(createWorkInboundStatusBadge("panel", panelEnabled, "text"));
                workInboundDetailBadgesEl.appendChild(createWorkInboundStatusBadge("visibility", visibleForUsers, "text"));
            }
            if (workInboundDetailToggleBtnEl) {
                workInboundDetailToggleBtnEl.textContent = visibleForUsers
                    ? "Скрыть у пользователей"
                    : "Показывать пользователям";
                workInboundDetailToggleBtnEl.dataset.panelInboundId = String(panelInboundRefId);
                workInboundDetailToggleBtnEl.dataset.nextVisible = visibleForUsers ? "false" : "true";
                workInboundDetailToggleBtnEl.disabled = false;
            }
            if (workInboundDetailNoteEl) {
                workInboundDetailNoteEl.textContent = "Управляй видимостью и клиентами этого подключения.";
            }
            setInboundDetailAddStatus("");
        }

        async function openWorkInboundDetail(panelInboundRefIdRaw) {
            const panelInboundRefId = Number(panelInboundRefIdRaw || 0);
            if (!panelInboundRefId) return;
            renderWorkInboundDetail(panelInboundRefId);
            if (!workState.selectedInboundPanelId) return;
            switchWorkPage("work-inbound-detail-page");
            renderWorkInboundDetailClients([], "Загрузка клиентов...");
            await loadWorkInboundDetailClients(panelInboundRefId);
        }

        async function createWorkInboundClient() {
            const panelInboundRefId = Number(workState.selectedInboundPanelId || 0);
            if (!panelInboundRefId) {
                throw new Error("Сначала открой подключение");
            }
            const label = String(workInboundDetailNewClientLabelEl?.value || "").trim();
            if (!label) {
                throw new Error("Введи название клиента");
            }

            setInboundDetailAddStatus("Создаем клиента...");
            const result = await postJson(adminInboundClientsUrl(panelInboundRefId), { label });
            if (Array.isArray(result?.clients)) {
                renderWorkInboundDetailClients(result.clients);
            } else {
                await loadWorkInboundDetailClients(panelInboundRefId);
            }
            if (workInboundDetailNewClientLabelEl) {
                workInboundDetailNewClientLabelEl.value = "";
            }
            const warning = String(result?.warning || "").trim();
            setInboundDetailAddStatus(warning ? `Клиент добавлен. ${warning}` : "Клиент добавлен.", "success");
            return result;
        }

        async function toggleWorkInboundVisibility(panelInboundRefIdRaw, nextVisibleRaw) {
            const panelInboundRefId = Number(panelInboundRefIdRaw || 0);
            if (!panelInboundRefId) return;
            const nextVisible = String(nextVisibleRaw) === "true";

            await runWorkAction("Toggle Inbound Visibility", async () => {
                const result = await postJson(adminInboundVisibilityUrl(panelInboundRefId), {
                    show_in_app: nextVisible,
                });
                const updated = result?.inbound || null;
                if (updated) {
                    workState.inbounds = workState.inbounds.map((row) =>
                        String(row?.panel_inbound_ref_id) === String(updated.panel_inbound_ref_id)
                            ? { ...row, ...updated }
                            : row
                    );
                } else {
                    await loadWorkClientsData();
                }

                renderWorkInboundsManager();
                renderWorkInboundSelectOptions();
                renderWorkPendingInboundSelectOptions();
                if (workState.selectedPanelId) {
                    renderWorkPanelInbounds(workState.selectedPanelId);
                }
                if (String(workState.selectedInboundPanelId) === String(panelInboundRefId)) {
                    renderWorkInboundDetail(panelInboundRefId);
                }
                return result;
            });
        }

        function renderWorkInboundsManager() {
            if (!workInboundsListEl) return;
            workInboundsListEl.innerHTML = "";

            const rows = Array.isArray(workState.inbounds) ? workState.inbounds : [];
            if (!rows.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Подключения не найдены. Нажми «Синхр.»";
                workInboundsListEl.appendChild(empty);
                return;
            }

            rows.forEach((inbound) => {
                const panelInboundRefId = Number(inbound?.panel_inbound_ref_id || 0);
                const externalInboundId = inbound?.panel_inbound_id ?? "—";
                const panelEnabled = Boolean(inbound?.enable);
                const visibleForUsers = Boolean(inbound?.show_in_app);

                const card = document.createElement("div");
                card.className = "work-inbound-card interactive";
                card.tabIndex = 0;
                card.setAttribute("role", "button");
                card.setAttribute("aria-label", `Развернуть подключение ${externalInboundId}`);

                const head = document.createElement("div");
                head.className = "work-inbound-head";

                const title = document.createElement("div");
                title.className = "work-inbound-title";
                title.textContent = String(inbound?.remark || `Inbound ${externalInboundId}`).trim() || `Inbound ${externalInboundId}`;

                const badges = document.createElement("div");
                badges.className = "work-inbound-badges";

                const panelBadge = createWorkInboundStatusBadge("panel", panelEnabled);
                const visibilityBadge = createWorkInboundStatusBadge("visibility", visibleForUsers);
                const expandHint = document.createElement("div");
                expandHint.className = "work-inbound-expand-hint";
                expandHint.textContent = "⤢";
                expandHint.title = "Развернуть";

                badges.appendChild(panelBadge);
                badges.appendChild(visibilityBadge);
                head.appendChild(title);
                head.appendChild(badges);
                head.appendChild(expandHint);

                const meta = document.createElement("div");
                meta.className = "work-inbound-meta";
                const protocol = String(inbound?.protocol || "unknown").toLowerCase();
                const panelName = String(inbound?.panel_name || "").trim() || "—";
                const region = String(inbound?.region || "").trim();
                const panelLabel = `${panelName}${region ? ` (${region})` : ""}`;
                meta.textContent = `Панель: ${panelLabel} • #${externalInboundId} • ${protocol} • порт: ${inbound?.port ?? "—"}`;

                const openDetail = () => {
                    openWorkInboundDetail(panelInboundRefId).catch((err) => {
                        console.error("open inbound detail error:", err);
                        setInboundDetailAddStatus(err?.message || "Не удалось открыть подключение", "error");
                    });
                };
                card.addEventListener("click", openDetail);
                card.addEventListener("keydown", (event) => {
                    if (event.key !== "Enter" && event.key !== " ") return;
                    event.preventDefault();
                    openDetail();
                });

                card.appendChild(head);
                card.appendChild(meta);
                workInboundsListEl.appendChild(card);
            });
        }

        function parseBoolValue(value, fallback = true) {
            if (typeof value === "boolean") return value;
            if (typeof value === "number") return value !== 0;
            if (typeof value === "string") {
                const normalized = value.trim().toLowerCase();
                if (["1", "true", "yes", "on"].includes(normalized)) return true;
                if (["0", "false", "no", "off"].includes(normalized)) return false;
            }
            return fallback;
        }

        function parseIntInRange(value, fallback, minValue, maxValue) {
            const parsed = Number.parseInt(String(value ?? "").trim(), 10);
            let out = Number.isInteger(parsed) ? parsed : fallback;
            if (typeof minValue === "number") out = Math.max(minValue, out);
            if (typeof maxValue === "number") out = Math.min(maxValue, out);
            return out;
        }

        function setWorkSettingsStatus(message, tone = "") {
            if (!workSettingsSaveStatusEl) return;
            workSettingsSaveStatusEl.classList.remove("success", "error");
            if (!message) {
                workSettingsSaveStatusEl.textContent = "";
                workSettingsSaveStatusEl.classList.add("hidden");
                return;
            }
            if (tone === "success" || tone === "error") {
                workSettingsSaveStatusEl.classList.add(tone);
            }
            workSettingsSaveStatusEl.textContent = message;
            workSettingsSaveStatusEl.classList.remove("hidden");
        }

        function applyWorkSettingsFormValues(settingsMap) {
            const cloudVisible = parseBoolValue(settingsMap?.[systemSettingKeys.cloudVisibility], true);
            const chunkSizeMb = parseIntInRange(settingsMap?.[systemSettingKeys.cloudChunkSizeMb], 15, 1, 20);
            const sendTimeoutSec = parseIntInRange(settingsMap?.[systemSettingKeys.cloudSendTimeoutSec], 300, 30, 1800);
            const sendRetries = parseIntInRange(settingsMap?.[systemSettingKeys.cloudSendRetries], 3, 1, 10);
            const sendRetryDelaySec = parseIntInRange(settingsMap?.[systemSettingKeys.cloudSendRetryDelaySec], 2, 1, 60);

            if (workSettingCloudVisibilityEl) {
                workSettingCloudVisibilityEl.value = cloudVisible ? "true" : "false";
            }
            if (workSettingCloudChunkMbEl) {
                workSettingCloudChunkMbEl.value = String(chunkSizeMb);
            }
            if (workSettingCloudSendTimeoutEl) {
                workSettingCloudSendTimeoutEl.value = String(sendTimeoutSec);
            }
            if (workSettingCloudSendRetriesEl) {
                workSettingCloudSendRetriesEl.value = String(sendRetries);
            }
            if (workSettingCloudSendRetryDelayEl) {
                workSettingCloudSendRetryDelayEl.value = String(sendRetryDelaySec);
            }
        }

        async function loadWorkSystemSettings() {
            setWorkSettingsStatus("", "");
            const resp = await fetchJson(`${adminSettingsUrl}?prefix=cloud.`, false);
            const rows = Array.isArray(resp?.settings) ? resp.settings : [];
            const settingsMap = {};
            rows.forEach((row) => {
                const key = String(row?.key || "").trim();
                if (!key) return;
                settingsMap[key] = row?.value;
            });
            workState.settings = settingsMap;
            applyWorkSettingsFormValues(settingsMap);
            return settingsMap;
        }

        async function saveWorkSystemSettings() {
            const cloudVisible = workSettingCloudVisibilityEl?.value !== "false";
            const chunkSizeMb = parseIntInRange(workSettingCloudChunkMbEl?.value, 15, 1, 20);
            const sendTimeoutSec = parseIntInRange(workSettingCloudSendTimeoutEl?.value, 300, 30, 1800);
            const sendRetries = parseIntInRange(workSettingCloudSendRetriesEl?.value, 3, 1, 10);
            const sendRetryDelaySec = parseIntInRange(workSettingCloudSendRetryDelayEl?.value, 2, 1, 60);

            const payloads = [
                {
                    key: systemSettingKeys.cloudVisibility,
                    value: cloudVisible,
                    description: "Show or hide Cloud section in app",
                },
                {
                    key: systemSettingKeys.cloudChunkSizeMb,
                    value: chunkSizeMb,
                    description: "Cloud upload chunk size in megabytes",
                },
                {
                    key: systemSettingKeys.cloudSendTimeoutSec,
                    value: sendTimeoutSec,
                    description: "Telegram send timeout in seconds",
                },
                {
                    key: systemSettingKeys.cloudSendRetries,
                    value: sendRetries,
                    description: "Telegram send retry attempts",
                },
                {
                    key: systemSettingKeys.cloudSendRetryDelaySec,
                    value: sendRetryDelaySec,
                    description: "Telegram send retry delay in seconds",
                },
            ];

            for (const item of payloads) {
                await postJson(adminSettingUrl(item.key), {
                    value: item.value,
                    description: item.description,
                });
            }

            await loadWorkSystemSettings();
            applyCloudVisibility({ features: { cloud_enabled: cloudVisible } });
            return payloads;
        }

        function setWorkPanelStatus(message, tone = "") {
            if (!workPanelStatusEl) return;
            workPanelStatusEl.classList.remove("success", "error");
            if (!message) {
                workPanelStatusEl.textContent = "";
                workPanelStatusEl.classList.add("hidden");
                return;
            }
            if (tone === "success" || tone === "error") {
                workPanelStatusEl.classList.add(tone);
            }
            workPanelStatusEl.textContent = message;
            workPanelStatusEl.classList.remove("hidden");
        }

        function setWorkPanelDetailStatus(message, tone = "") {
            if (!workPanelDetailStatusEl) return;
            workPanelDetailStatusEl.classList.remove("success", "error");
            if (!message) {
                workPanelDetailStatusEl.textContent = "";
                workPanelDetailStatusEl.classList.add("hidden");
                return;
            }
            if (tone === "success" || tone === "error") {
                workPanelDetailStatusEl.classList.add(tone);
            }
            workPanelDetailStatusEl.textContent = message;
            workPanelDetailStatusEl.classList.remove("hidden");
        }

        function panelHealthBadgeClass(healthRaw) {
            const health = String(healthRaw || "unknown").trim().toLowerCase();
            if (health === "green") return "visibility-on";
            if (health === "yellow") return "visibility-off";
            if (health === "red") return "panel-off";
            return "panel-off";
        }

        function findWorkPanelById(panelIdRaw) {
            const panelId = String(panelIdRaw || "").trim();
            if (!panelId) return null;
            return workState.panels.find((row) => String(row?.id || "").trim() === panelId) || null;
        }

        function getWorkPanelInbounds(panelIdRaw) {
            const panelId = String(panelIdRaw || "").trim();
            if (!panelId) return [];
            return (Array.isArray(workState.inbounds) ? workState.inbounds : []).filter(
                (row) => String(row?.panel_id || "").trim() === panelId
            );
        }

        function collectWorkPanelPayload() {
            return {
                name: String(workPanelNameEl?.value || "").trim(),
                provider: String(workPanelProviderEl?.value || "3xui").trim(),
                base_url: String(workPanelBaseUrlEl?.value || "").trim(),
                region: String(workPanelRegionEl?.value || "").trim() || null,
                auth_type: "login_password",
                username: String(workPanelUsernameEl?.value || "").trim(),
                password: String(workPanelPasswordEl?.value || "").trim(),
            };
        }

        function collectWorkPanelDetailAccessPayload() {
            return {
                base_url: String(workPanelDetailBaseUrlEl?.value || "").trim(),
                username: String(workPanelDetailUsernameEl?.value || "").trim(),
                password: String(workPanelDetailPasswordEl?.value || "").trim(),
            };
        }

        function toggleWorkPanelAccessSection(forceVisible = null) {
            if (!workPanelDetailAccessWrapEl || !workPanelDetailAccessBtnEl) return;
            const nextVisible = forceVisible === null
                ? workPanelDetailAccessWrapEl.classList.contains("hidden")
                : Boolean(forceVisible);
            workPanelDetailAccessWrapEl.classList.toggle("hidden", !nextVisible);
            workPanelDetailAccessBtnEl.textContent = nextVisible
                ? "Скрыть настройки доступа"
                : "Настройки доступа";
        }

        function renderWorkPanelInbounds(panelIdRaw) {
            if (!workPanelDetailInboundsListEl) return;
            workPanelDetailInboundsListEl.innerHTML = "";

            const panelId = String(panelIdRaw || "").trim();
            if (!panelId) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Сначала открой панель.";
                workPanelDetailInboundsListEl.appendChild(empty);
                return;
            }

            const rows = getWorkPanelInbounds(panelId);
            if (!rows.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "У панели пока нет синхронизированных подключений.";
                workPanelDetailInboundsListEl.appendChild(empty);
                return;
            }

            rows.forEach((inbound) => {
                const panelInboundRefId = Number(inbound?.panel_inbound_ref_id || 0);
                const externalInboundId = inbound?.panel_inbound_id ?? "—";
                const panelEnabled = Boolean(inbound?.enable);
                const visibleForUsers = Boolean(inbound?.show_in_app);

                const card = document.createElement("div");
                card.className = "work-inbound-card interactive";
                if (String(workState.selectedInboundPanelId || "") === String(panelInboundRefId)) {
                    card.classList.add("active");
                }
                card.tabIndex = 0;
                card.setAttribute("role", "button");
                card.setAttribute("aria-label", `Открыть подключение ${externalInboundId}`);

                const head = document.createElement("div");
                head.className = "work-inbound-head";

                const title = document.createElement("div");
                title.className = "work-inbound-title";
                title.textContent = String(inbound?.remark || `Inbound ${externalInboundId}`).trim() || `Inbound ${externalInboundId}`;

                const badges = document.createElement("div");
                badges.className = "work-inbound-badges";
                badges.appendChild(createWorkInboundStatusBadge("panel", panelEnabled));
                badges.appendChild(createWorkInboundStatusBadge("visibility", visibleForUsers));

                head.appendChild(title);
                head.appendChild(badges);
                card.appendChild(head);

                const meta = document.createElement("div");
                meta.className = "work-inbound-meta";
                const protocol = String(inbound?.protocol || "unknown").toLowerCase();
                meta.textContent = `#${externalInboundId} • ${protocol} • порт: ${inbound?.port ?? "—"}`;
                card.appendChild(meta);

                const hint = document.createElement("div");
                hint.className = "work-inbound-meta";
                hint.textContent = visibleForUsers
                    ? "Нажми, чтобы открыть и настроить подключение."
                    : "Подключение скрыто для пользователей. Нажми, чтобы настроить.";
                card.appendChild(hint);

                const openDetail = () => {
                    openWorkInboundDetail(panelInboundRefId).catch((err) => {
                        console.error("open panel inbound detail error:", err);
                        setWorkPanelDetailStatus(err?.message || "Не удалось открыть подключение", "error");
                    });
                };
                card.addEventListener("click", openDetail);
                card.addEventListener("keydown", (event) => {
                    if (event.key !== "Enter" && event.key !== " ") return;
                    event.preventDefault();
                    openDetail();
                });

                workPanelDetailInboundsListEl.appendChild(card);
            });
        }

        function clearWorkPanelDetail(note = "Выбери панель в списке.") {
            workState.selectedPanelId = null;
            if (workPanelDetailTitleEl) {
                workPanelDetailTitleEl.textContent = "Панель";
            }
            if (workPanelDetailMetaEl) {
                workPanelDetailMetaEl.textContent = "—";
            }
            if (workPanelDetailBadgesEl) {
                workPanelDetailBadgesEl.innerHTML = "";
            }
            if (workPanelDetailSummaryEl) {
                workPanelDetailSummaryEl.innerHTML = "";
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = note;
                workPanelDetailSummaryEl.appendChild(empty);
            }
            if (workPanelDetailActivateBtnEl) {
                workPanelDetailActivateBtnEl.removeAttribute("data-panel-id");
                workPanelDetailActivateBtnEl.textContent = "Активировать панель";
            }
            if (workPanelDetailSyncBtnEl) {
                workPanelDetailSyncBtnEl.removeAttribute("data-panel-id");
            }
            if (workPanelDetailAccessBtnEl) {
                workPanelDetailAccessBtnEl.removeAttribute("data-panel-id");
                workPanelDetailAccessBtnEl.textContent = "Настройки доступа";
            }
            if (workPanelDetailTestBtnEl) {
                workPanelDetailTestBtnEl.removeAttribute("data-panel-id");
            }
            if (workPanelDetailSaveBtnEl) {
                workPanelDetailSaveBtnEl.removeAttribute("data-panel-id");
            }
            if (workPanelDetailDeleteBtnEl) {
                workPanelDetailDeleteBtnEl.removeAttribute("data-panel-id");
            }
            if (workPanelDetailBaseUrlEl) {
                workPanelDetailBaseUrlEl.value = "";
            }
            if (workPanelDetailUsernameEl) {
                workPanelDetailUsernameEl.value = "";
            }
            if (workPanelDetailPasswordEl) {
                workPanelDetailPasswordEl.value = "";
            }
            if (workPanelDetailInboundsListEl) {
                workPanelDetailInboundsListEl.innerHTML = "";
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Сначала открой панель.";
                workPanelDetailInboundsListEl.appendChild(empty);
            }
            toggleWorkPanelAccessSection(false);
            setWorkPanelDetailStatus("");
        }

        function renderWorkPanelDetail(panelIdRaw) {
            const panel = findWorkPanelById(panelIdRaw);
            if (!panel) {
                clearWorkPanelDetail("Панель не найдена.");
                return;
            }
            workState.selectedPanelId = panel.id;
            const panelName = String(panel?.name || "Panel").trim() || "Panel";
            const region = String(panel?.region || "").trim();
            const provider = String(panel?.provider || "").trim() || "provider";
            const health = String(panel?.health_status || "unknown").trim().toLowerCase() || "unknown";
            const panelInbounds = getWorkPanelInbounds(panel.id);

            if (workPanelDetailTitleEl) {
                workPanelDetailTitleEl.textContent = `${panelName}${region ? ` (${region})` : ""}`;
            }
            if (workPanelDetailMetaEl) {
                workPanelDetailMetaEl.textContent = `Тип: ${provider} • Локация: ${region || "—"} • inbound: ${panelInbounds.length}`;
            }
            if (workPanelDetailBadgesEl) {
                workPanelDetailBadgesEl.innerHTML = "";
                const healthBadge = document.createElement("span");
                healthBadge.className = `work-inbound-pill ${panelHealthBadgeClass(health)} text`;
                healthBadge.textContent = `health: ${health}`;
                workPanelDetailBadgesEl.appendChild(healthBadge);
                workPanelDetailBadgesEl.appendChild(createWorkInboundStatusBadge("panel", Boolean(panel?.is_active), "text"));
            }

            if (workPanelDetailSummaryEl) {
                workPanelDetailSummaryEl.innerHTML = "";
                const rows = [
                    ["Название", panelName],
                    ["Провайдер", provider],
                    ["Локация", region || "—"],
                    ["Состояние", health],
                    ["Активность", panel?.is_active ? "active" : "inactive"],
                    ["Подключения", String(panelInbounds.length)],
                    ["Последняя успешная проверка", panel?.last_ok_at ? fmtDateTime(panel.last_ok_at) : "—"],
                ];
                if (panel?.error_message) {
                    rows.push(["Последняя ошибка", String(panel.error_message).trim()]);
                }
                rows.forEach(([label, value]) => {
                    const row = document.createElement("div");
                    row.className = "work-link-item";
                    const title = document.createElement("div");
                    title.className = "work-link-item-title";
                    title.textContent = label;
                    const sub = document.createElement("div");
                    sub.className = "work-link-item-sub";
                    sub.textContent = value || "—";
                    row.appendChild(title);
                    row.appendChild(sub);
                    workPanelDetailSummaryEl.appendChild(row);
                });
            }

            if (workPanelDetailActivateBtnEl) {
                workPanelDetailActivateBtnEl.dataset.panelId = panel.id;
                workPanelDetailActivateBtnEl.textContent = panel?.is_active ? "Деактивировать панель" : "Активировать панель";
            }
            if (workPanelDetailSyncBtnEl) {
                workPanelDetailSyncBtnEl.dataset.panelId = panel.id;
            }
            if (workPanelDetailAccessBtnEl) {
                workPanelDetailAccessBtnEl.dataset.panelId = panel.id;
            }
            if (workPanelDetailTestBtnEl) {
                workPanelDetailTestBtnEl.dataset.panelId = panel.id;
            }
            if (workPanelDetailSaveBtnEl) {
                workPanelDetailSaveBtnEl.dataset.panelId = panel.id;
            }
            if (workPanelDetailDeleteBtnEl) {
                workPanelDetailDeleteBtnEl.dataset.panelId = panel.id;
            }
            if (workPanelDetailBaseUrlEl) {
                workPanelDetailBaseUrlEl.value = String(panel?.base_url || "").trim();
            }
            if (workPanelDetailUsernameEl) {
                workPanelDetailUsernameEl.value = "";
            }
            if (workPanelDetailPasswordEl) {
                workPanelDetailPasswordEl.value = "";
            }
            renderWorkPanelInbounds(panel.id);
            toggleWorkPanelAccessSection(false);
            setWorkPanelDetailStatus("");
        }

        async function openWorkPanelDetail(panelIdRaw) {
            const panelId = String(panelIdRaw || "").trim();
            if (!panelId) return;
            if (!Array.isArray(workState.panels) || !workState.panels.length) {
                await loadWorkPanels();
            }
            renderWorkPanelDetail(panelId);
            switchWorkPage("work-panel-detail-page");
        }

        async function toggleWorkPanelActive(panel) {
            const nextActive = !Boolean(panel?.is_active);
            await postJson(adminPanelActionUrl(panel.id, "activate"), { is_active: nextActive });
            await loadWorkPanels();
        }

        async function syncWorkPanel(panel) {
            await postJson(adminPanelActionUrl(panel.id, "sync-inbounds"), {});
            await loadWorkPanels();
        }

        async function testWorkPanelDetailConnection(panelIdRaw) {
            const panel = findWorkPanelById(panelIdRaw);
            if (!panel) {
                throw new Error("Панель не найдена");
            }
            const payload = collectWorkPanelDetailAccessPayload();
            const baseUrl = payload.base_url || String(panel?.base_url || "").trim();
            if (!baseUrl) {
                throw new Error("Укажи URL панели");
            }
            if (!payload.username || !payload.password) {
                throw new Error("Для проверки укажи login и password");
            }
            return postJson(adminPanelsTestUrl, {
                name: String(panel?.name || "Panel").trim() || "Panel",
                provider: String(panel?.provider || "3xui").trim() || "3xui",
                base_url: baseUrl,
                auth_type: "login_password",
                username: payload.username,
                password: payload.password,
            });
        }

        async function saveWorkPanelDetailAccess(panelIdRaw) {
            const panel = findWorkPanelById(panelIdRaw);
            if (!panel) {
                throw new Error("Панель не найдена");
            }
            const payload = collectWorkPanelDetailAccessPayload();
            let updated = false;

            if (payload.base_url && payload.base_url !== String(panel?.base_url || "").trim()) {
                await postJson(adminPanelUpdateUrl(panel.id), { base_url: payload.base_url });
                updated = true;
            }

            const hasUsername = Boolean(payload.username);
            const hasPassword = Boolean(payload.password);
            if (hasUsername !== hasPassword) {
                throw new Error("Укажи и login, и password");
            }
            if (hasUsername && hasPassword) {
                await postJson(adminPanelActionUrl(panel.id, "rotate-secret"), {
                    username: payload.username,
                    password: payload.password,
                });
                updated = true;
            }

            if (!updated) {
                throw new Error("Нет изменений для сохранения");
            }

            await loadWorkPanels();
            renderWorkPanelDetail(panel.id);
            return { ok: true };
        }

        async function deleteWorkPanel(panelIdRaw) {
            const panel = findWorkPanelById(panelIdRaw);
            if (!panel) {
                throw new Error("Панель не найдена");
            }

            const panelName = String(panel?.name || "Panel").trim() || "Panel";
            const confirmed = window.confirm(`Удалить панель "${panelName}" и все связанные подключения?`);
            if (!confirmed) {
                return { canceled: true };
            }

            setWorkPanelDetailStatus("Удаляем панель...");
            const deletedInboundIds = new Set(
                getWorkPanelInbounds(panel.id).map((row) => String(row?.panel_inbound_ref_id || "").trim())
            );
            const result = await postJson(adminPanelActionUrl(panel.id, "delete"), {});

            if (deletedInboundIds.has(String(workState.selectedInboundPanelId || "").trim())) {
                clearWorkInboundDetail("Подключение удалено вместе с панелью.");
            }

            workState.selectedPanelId = null;
            switchWorkPage("work-panels-page");
            setWorkPanelStatus(`Панель "${panelName}" удалена`, "success");
            return result;
        }

        function renderWorkPanelsList(panels) {
            if (!workPanelsListEl) return;
            workPanelsListEl.innerHTML = "";
            const rows = Array.isArray(panels) ? panels : [];
            if (!rows.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Панели еще не добавлены.";
                workPanelsListEl.appendChild(empty);
                return;
            }

            rows.forEach((panel) => {
                const card = document.createElement("div");
                card.className = "work-inbound-card interactive";
                if (String(workState.selectedPanelId || "") === String(panel?.id || "")) {
                    card.classList.add("active");
                }
                card.tabIndex = 0;
                card.setAttribute("role", "button");
                card.setAttribute("aria-label", `Открыть панель ${panel?.name || ""}`);

                const head = document.createElement("div");
                head.className = "work-inbound-head";

                const title = document.createElement("div");
                title.className = "work-inbound-title";
                const region = String(panel?.region || "").trim();
                title.textContent = `${panel?.name || "Panel"}${region ? ` (${region})` : ""}`;

                const badges = document.createElement("div");
                badges.className = "work-inbound-badges";
                const health = String(panel?.health_status || "unknown").toLowerCase();
                const healthBadge = document.createElement("span");
                healthBadge.className = `work-inbound-pill ${panelHealthBadgeClass(health)} text`;
                healthBadge.textContent = `health: ${health}`;
                badges.appendChild(healthBadge);
                badges.appendChild(createWorkInboundStatusBadge("panel", Boolean(panel?.is_active), "text"));

                head.appendChild(title);
                head.appendChild(badges);
                card.appendChild(head);

                const meta = document.createElement("div");
                meta.className = "work-inbound-meta";
                meta.textContent = `Тип: ${panel?.provider || "provider"} • Локация: ${region || "—"}`;
                card.appendChild(meta);

                const hint = document.createElement("div");
                hint.className = "work-inbound-meta";
                hint.textContent = "Нажми, чтобы открыть панель";
                card.appendChild(hint);

                const openPanel = () => {
                    openWorkPanelDetail(panel?.id).catch((err) => {
                        console.error("open panel detail error:", err);
                        setWorkPanelDetailStatus(err?.message || "Не удалось открыть панель", "error");
                    });
                };
                card.addEventListener("click", openPanel);
                card.addEventListener("keydown", (event) => {
                    if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        openPanel();
                    }
                });

                workPanelsListEl.appendChild(card);
            });
        }

        async function loadWorkPanels() {
            const [panelsResp, inboundsResp] = await Promise.all([
                fetchJson(adminPanelsUrl, false),
                fetchJson(adminInboundsUrl, false),
            ]);
            const rows = Array.isArray(panelsResp?.panels) ? panelsResp.panels : [];
            workState.panels = rows;
            workState.inbounds = Array.isArray(inboundsResp?.inbounds) ? inboundsResp.inbounds : [];
            renderWorkPanelsList(rows);
            renderWorkInboundsManager();
            renderWorkInboundSelectOptions();
            renderWorkPendingInboundSelectOptions();
            if (workState.selectedPanelId) {
                renderWorkPanelDetail(workState.selectedPanelId);
            }
            if (workState.selectedInboundPanelId) {
                renderWorkInboundDetail(workState.selectedInboundPanelId);
            }
            return rows;
        }

        async function testWorkPanelConnection() {
            const payload = collectWorkPanelPayload();
            if (!payload.base_url) {
                throw new Error("Укажи URL панели");
            }
            const result = await postJson(adminPanelsTestUrl, payload);
            return result;
        }

        async function saveWorkPanel() {
            const payload = collectWorkPanelPayload();
            if (!payload.name) {
                throw new Error("Укажи имя панели");
            }
            if (!payload.base_url) {
                throw new Error("Укажи URL панели");
            }
            const result = await postJson(adminPanelsUrl, payload);
            await loadWorkPanels();
            return result;
        }

        function renderExistingBindings(bindings) {
            if (!workExistingLinksEl) return;
            workExistingLinksEl.innerHTML = "";

            if (!Array.isArray(bindings) || !bindings.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Связей пока нет.";
                workExistingLinksEl.appendChild(empty);
                return;
            }

            const groups = new Map();
            bindings.forEach((binding) => {
                const inboundId = binding.panel_inbound_id ?? "—";
                const connectionName = (binding.inbound_remark || "").trim() || `Inbound ${inboundId}`;
                const inboundRefId = binding.panel_inbound_ref_id ?? "—";
                const panelName = String(binding.panel_name || "").trim() || "—";
                const key = `${panelName}::${inboundRefId}::${connectionName}`;
                if (!groups.has(key)) {
                    groups.set(key, {
                        connectionName,
                        panelName,
                        clients: [],
                        statuses: [],
                        latestUpdated: null,
                    });
                }
                const group = groups.get(key);
                const label = String(binding.label || binding.identifier || "—").trim() || "—";
                const status = String(binding.status || "—").trim() || "—";
                group.clients.push({
                    id: binding.id,
                    label,
                });
                if (!group.statuses.includes(status)) group.statuses.push(status);

                const updated = binding.updated_at ? new Date(binding.updated_at) : null;
                if (updated && !Number.isNaN(updated.getTime())) {
                    if (!group.latestUpdated || updated > group.latestUpdated) {
                        group.latestUpdated = updated;
                    }
                }
            });

            groups.forEach((group) => {
                const item = document.createElement("div");
                item.className = "work-link-item";

                const title = document.createElement("div");
                title.className = "work-link-item-title";
                title.textContent = group.connectionName;

                const panelLine = document.createElement("div");
                panelLine.className = "work-link-item-sub";
                panelLine.textContent = `панель: ${group.panelName}`;

                const statusLine = document.createElement("div");
                statusLine.className = "work-link-item-sub";
                statusLine.textContent = `status: ${group.statuses.join(" • ") || "—"}`;

                const updatedLine = document.createElement("div");
                updatedLine.className = "work-link-item-sub";
                updatedLine.textContent = `обновлено: ${group.latestUpdated ? fmtDateTime(group.latestUpdated.toISOString()) : "—"}`;

                const clientsWrap = document.createElement("div");
                clientsWrap.className = "work-link-clients";
                group.clients.forEach((client) => {
                    const row = document.createElement("div");
                    row.className = "work-link-client";

                    const name = document.createElement("div");
                    name.className = "work-link-client-name";
                    name.textContent = client.label;

                    const removeBtn = document.createElement("button");
                    removeBtn.type = "button";
                    removeBtn.className = "work-link-client-remove";
                    removeBtn.textContent = "Удалить";
                    removeBtn.addEventListener("click", async (event) => {
                        event.stopPropagation();
                        await runWorkAction("Delete Binding", async () => {
                            await postJson(adminUnbindClientUrl, { binding_id: client.id });
                            await loadSelectedUserBindings();
                            await loadSelectedUserOverview();
                            return { deleted: client.id };
                        });
                    });

                    row.appendChild(name);
                    row.appendChild(removeBtn);
                    clientsWrap.appendChild(row);
                });

                item.appendChild(title);
                item.appendChild(panelLine);
                item.appendChild(statusLine);
                item.appendChild(updatedLine);
                item.appendChild(clientsWrap);
                workExistingLinksEl.appendChild(item);
            });
        }

        function resolveInboundClientSelection(inboundSelectEl, clientSelectEl, clients, emptyMessage) {
            const panelInboundRefId = inboundSelectEl?.value;
            const clientIndex = clientSelectEl?.value;
            if (!panelInboundRefId || clientIndex === "") {
                throw new Error(emptyMessage || "Выбери inbound и клиента");
            }

            const inbound = workState.inbounds.find((i) => String(i.panel_inbound_ref_id) === String(panelInboundRefId));
            const client = Array.isArray(clients) ? clients[Number(clientIndex)] : null;
            if (!client || !inbound) {
                throw new Error("Данные inbound/client не найдены");
            }
            return { panelInboundRefId: Number(panelInboundRefId), inbound, client };
        }

        function renderPendingBindings(rows) {
            if (!workPendingListEl) return;
            workPendingListEl.innerHTML = "";

            if (!Array.isArray(rows) || !rows.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Pending-привязок пока нет.";
                workPendingListEl.appendChild(empty);
                return;
            }

            rows.forEach((row) => {
                const item = document.createElement("div");
                item.className = "work-link-item";

                const title = document.createElement("div");
                title.className = "work-link-item-title";
                title.textContent = row?.inbound_remark || row?.label || row?.identifier || `Inbound ${row?.panel_inbound_id ?? "—"}`;

                const line1 = document.createElement("div");
                line1.className = "work-link-item-sub";
                line1.textContent = `TG: ${row?.telegram_id || "—"} • client: ${row?.label || row?.identifier || "—"}`;

                const line2 = document.createElement("div");
                line2.className = "work-link-item-sub";
                line2.textContent = `панель: ${row?.panel_name || "—"} • status: ${row?.status || "—"} • protocol: ${row?.protocol || "—"}`;

                item.appendChild(title);
                item.appendChild(line1);
                item.appendChild(line2);

                if (String(row?.status || "").toLowerCase() === "pending") {
                    const rowActions = document.createElement("div");
                    rowActions.className = "work-link-clients";

                    const rowActionWrap = document.createElement("div");
                    rowActionWrap.className = "work-link-client";

                    const rowActionName = document.createElement("div");
                    rowActionName.className = "work-link-client-name";
                    rowActionName.textContent = "Ожидает первого входа";

                    const cancelBtn = document.createElement("button");
                    cancelBtn.type = "button";
                    cancelBtn.className = "work-link-client-remove";
                    cancelBtn.textContent = "Отменить";
                    cancelBtn.addEventListener("click", async (event) => {
                        event.stopPropagation();
                        await runWorkAction("Cancel Pending Binding", async () => {
                            await postJson(adminCancelPendingBindingUrl(row.id));
                            await loadPendingBindings(workPendingTelegramIdEl?.value);
                            return { canceled: row.id };
                        });
                    });

                    rowActionWrap.appendChild(rowActionName);
                    rowActionWrap.appendChild(cancelBtn);
                    rowActions.appendChild(rowActionWrap);
                    item.appendChild(rowActions);
                }

                workPendingListEl.appendChild(item);
            });
        }

        async function loadPendingBindings(telegramIdRaw) {
            const telegramId = String(telegramIdRaw || "").trim();
            if (!telegramId) {
                workState.pendingBindings = [];
                renderPendingBindings([]);
                return { ok: true, pending_bindings: [] };
            }
            const url = `${adminPendingBindingsUrl}?telegram_id=${encodeURIComponent(telegramId)}&limit=200`;
            const resp = await fetchJson(url, false);
            workState.pendingBindings = Array.isArray(resp?.pending_bindings) ? resp.pending_bindings : [];
            renderPendingBindings(workState.pendingBindings);
            return resp;
        }

        function renderWorkClientOverview(overview) {
            workState.overview = overview || null;
            const sub = overview?.subscription || null;
            const conn = overview?.connections || null;

            if (workSubStatusSelectEl) {
                workSubStatusSelectEl.value = sub?.status || "active";
            }
            if (workSubPriceInputEl) {
                workSubPriceInputEl.value = sub?.price_amount ?? "";
            }
            if (workSubLimitInputEl) {
                workSubLimitInputEl.value =
                    conn?.limit === null || conn?.limit === undefined ? "" : String(conn.limit);
            }
            renderWorkSubscriptionControls(sub);

            workClientSubStatusEl.textContent = sub?.status || "нет";
            workClientSubUntilEl.textContent = formatSubscriptionUntil(sub, fmtDateTime);
            workClientSubPriceEl.textContent = fmtMoney(sub?.price_amount);

            if (!conn) {
                workClientConnectionsAvailableEl.textContent = "—";
            } else if (conn.limit === null || conn.limit === undefined) {
                workClientConnectionsAvailableEl.textContent = `${conn.active ?? 0}/∞`;
            } else {
                workClientConnectionsAvailableEl.textContent = `${conn.active ?? 0}/${conn.limit}`;
            }
        }
        async function loadSelectedUserOverview() {
            if (!workState.selectedUserId) {
                renderWorkClientOverview(null);
                return { ok: true, overview: null };
            }
            const resp = await fetchJson(adminUserOverviewUrl(workState.selectedUserId), false);
            renderWorkClientOverview(resp?.overview || null);
            return resp;
        }

        function setSelectedWorkClient(user) {
            if (!user) {
                workClientPageTitleEl.textContent = "Клиент";
                workClientPageTitleEl.title = "Клиент";
                if (getActiveWorkPageId() === "work-client-page") {
                    updateWorkPageContext("work-client-page");
                }
                workClientNameEl.textContent = "—";
                workClientMetaEl.textContent = "—";
                renderWorkClientOverview(null);
                return;
            }
            const title = user.name || user.username || `Клиент #${user.id}`;
            workClientPageTitleEl.textContent = title;
            workClientPageTitleEl.title = title;
            if (getActiveWorkPageId() === "work-client-page") {
                updateWorkPageContext("work-client-page");
            }
            workClientNameEl.textContent = title;
            workClientMetaEl.textContent = `${user.id} · ${user.username ? `@${user.username}` : "—"}`;
        }

        async function loadWorkClientsData() {
            const [usersResp, inboundsResp] = await Promise.all([
                fetchJson(adminUsersUrl, false),
                fetchJson(adminInboundsUrl, false),
            ]);
            workState.users = Array.isArray(usersResp?.users) ? usersResp.users : [];
            workState.inbounds = Array.isArray(inboundsResp?.inbounds) ? inboundsResp.inbounds : [];
            renderWorkClientCards();
            renderWorkInboundsManager();
            renderWorkInboundSelectOptions();
            renderWorkPendingInboundSelectOptions();
            fillSelect(
                workClientSelectEl,
                [],
                () => "",
                () => "",
                "Select client from inbound"
            );
            fillSelect(
                workPendingClientSelectEl,
                [],
                () => "",
                () => "",
                "Select client from inbound"
            );
            workState.clients = [];
            workState.pendingClients = [];
            if (workPendingInboundSelectEl?.value) {
                await loadPendingInboundClients(workPendingInboundSelectEl.value);
            }
            const pendingTgId = workPendingTelegramIdEl?.value?.trim();
            if (pendingTgId) {
                await Promise.all([loadPendingBindings(pendingTgId), loadPendingSubscriptionOverview(pendingTgId)]);
            } else {
                workState.pendingBindings = [];
                renderPendingBindings([]);
                renderPendingSubscriptionOverview(null);
                setPendingSubscriptionStatus("Укажи Telegram ID и сохрани параметры подписки.");
            }
            return { users: workState.users.length, inbounds: workState.inbounds.length };
        }

        async function loadSelectedUserBindings() {
            if (!workState.selectedUserId) {
                workState.bindings = [];
                renderExistingBindings([]);
                return { bindings: 0 };
            }
            const resp = await fetchJson(adminUserBindingsUrl(workState.selectedUserId), false);
            workState.bindings = Array.isArray(resp?.bindings) ? resp.bindings : [];
            renderExistingBindings(workState.bindings);
            return { bindings: workState.bindings.length };
        }

        async function openWorkClientPage(userId) {
            const user = workState.users.find((u) => String(u.id) === String(userId));
            if (!user) {
                throw new Error("Клиент не найден");
            }

            workState.selectedUserId = user.id;
            setSelectedWorkClient(user);
            if (workPendingTelegramIdEl) {
                workPendingTelegramIdEl.value = user?.telegram_id ? String(user.telegram_id) : "";
            }
            if (workSubCreateDateEl) {
                workSubCreateDateEl.value = "";
            }
            switchWorkPage("work-client-page");

            fillSelect(
                workClientSelectEl,
                [],
                () => "",
                () => "",
                "Выбери клиента из inbound"
            );
            workState.clients = [];
            if (workInboundSelectEl?.value) {
                await loadInboundClients(workInboundSelectEl.value);
            }
            const pendingTgId = workPendingTelegramIdEl?.value?.trim();
            await Promise.all([
                loadSelectedUserBindings(),
                loadSelectedUserOverview(),
                pendingTgId ? loadPendingBindings(pendingTgId) : Promise.resolve(),
                pendingTgId ? loadPendingSubscriptionOverview(pendingTgId) : Promise.resolve(),
            ]);
        }

        async function loadInboundClients(panelInboundId) {
            if (!panelInboundId) {
                workState.clients = [];
                fillSelect(workClientSelectEl, [], () => "", () => "", "Выбери клиента из inbound");
                return;
            }
            const resp = await fetchJson(adminInboundClientsUrl(panelInboundId), false);
            workState.clients = Array.isArray(resp?.clients) ? resp.clients : [];
            fillSelect(
                workClientSelectEl,
                workState.clients,
                (c, idx) => `${idx + 1}. ${c.label || "Клиент"}`,
                (_, idx) => String(idx),
                "Выбери клиента из inbound"
            );
        }

        async function refreshInboundClientsFromPanel() {
            const panelInboundRefId = workInboundSelectEl?.value?.trim();
            if (!panelInboundRefId) {
                throw new Error("Сначала выбери inbound");
            }

            await postJson(adminSyncInboundsUrl);
            const inboundsResp = await fetchJson(adminInboundsUrl, false);
            workState.inbounds = Array.isArray(inboundsResp?.inbounds) ? inboundsResp.inbounds : [];
            renderWorkInboundsManager();
            renderWorkInboundSelectOptions();
            renderWorkPendingInboundSelectOptions();

            const exists = workState.inbounds.some((row) => String(row?.panel_inbound_ref_id) === panelInboundRefId);
            if (!exists) {
                workState.clients = [];
                fillSelect(workClientSelectEl, [], () => "", () => "", "Выбери клиента из inbound");
                throw new Error(`Inbound ${panelInboundRefId} не найден после обновления`);
            }

            if (workInboundSelectEl) {
                workInboundSelectEl.value = panelInboundRefId;
            }
            await loadInboundClients(panelInboundRefId);
            if (workPendingInboundSelectEl?.value === panelInboundRefId) {
                await loadPendingInboundClients(panelInboundRefId);
            }

            return { inbounds: workState.inbounds.length, clients: workState.clients.length };
        }


        async function loadPendingInboundClients(panelInboundId) {
            if (!panelInboundId) {
                workState.pendingClients = [];
                fillSelect(workPendingClientSelectEl, [], () => "", () => "", "Select client from inbound");
                return;
            }
            const resp = await fetchJson(adminInboundClientsUrl(panelInboundId), false);
            workState.pendingClients = Array.isArray(resp?.clients) ? resp.clients : [];
            fillSelect(
                workPendingClientSelectEl,
                workState.pendingClients,
                (c, idx) => `${idx + 1}. ${c.label || "Client"}`,
                (_, idx) => String(idx),
                "Select client from inbound"
            );
        }

        function switchWorkPage(target) {
            const next = target || "work-menu-page";
            const current = getActiveWorkPageId();
            if (current === "work-inbound-detail-page" && next !== "work-inbound-detail-page") {
                workState.selectedInboundPanelId = null;
                setInboundDetailAddStatus("");
            }
            if (current === "work-panel-detail-page" && next !== "work-panel-detail-page") {
                setWorkPanelDetailStatus("");
                toggleWorkPanelAccessSection(false);
            }
            if (next === "work-inbound-detail-page" && !workState.selectedInboundPanelId) {
                clearWorkInboundDetail();
            }
            if (next === "work-panel-detail-page" && !workState.selectedPanelId) {
                clearWorkPanelDetail();
            }
            workPages.forEach((page) => page.classList.toggle("hidden", page.id !== next));
            const hideWorkHeaders = next !== "work-menu-page";
            setTopbarVisibility(hideWorkHeaders);
            workSectionTitleEl?.classList.toggle("hidden", hideWorkHeaders);
            updateWorkPageContext(next);
            updateScreenMenuContext("screen-work");
            updateTelegramBackButton();
            if (next === "work-system-settings-page") {
                loadWorkSystemSettings().catch((err) => {
                    console.error("load system settings error:", err);
                    setWorkSettingsStatus(err?.message || "Не удалось загрузить настройки", "error");
                });
            }
            if (next === "work-panels-page") {
                loadWorkPanels().catch((err) => {
                    console.error("load panels error:", err);
                    setWorkPanelStatus(err?.message || "Не удалось загрузить панели", "error");
                });
            }
            if (next === "work-panel-create-page") {
                setWorkPanelStatus("");
            }
        }

        function switchScreen(target) {
            const previousScreen = getActiveScreenId();
            if (target === "screen-cloud" && !uiFeatures.cloudEnabled) {
                target = "screen-home";
            }
            heroCardEl?.classList.toggle("hidden", target !== "screen-home");
            navButtons.forEach((b) => b.classList.toggle("active", b.dataset.screen === target));
            screens.forEach((s) => s.classList.toggle("hidden", s.id !== target));
            if (target !== "screen-work") {
                setTopbarVisibility(false);
                workSectionTitleEl?.classList.remove("hidden");
            }
            if (target === "screen-work") {
                switchWorkPage("work-menu-page");
            }
            if (target !== "screen-connections") {
                openConnectionsMenu();
            }
            if (target !== "screen-cloud") {
                closeCloudPreview();
            }
            if (target !== "screen-work") {
                workState.selectedInboundPanelId = null;
                setInboundDetailAddStatus("");
                workState.selectedPanelId = null;
                clearWorkPanelDetail();
                setWorkPanelStatus("");
            }
            if (target === "screen-cloud") {
                if (previousScreen !== "screen-cloud") {
                    cloudState.path = "/";
                }
                ensureCloudLoaded(true).catch((err) => {
                    console.error("cloud init error:", err);
                    setCloudStatus(err?.message || "Не удалось загрузить облако", "error");
                });
            }
            updateScreenMenuContext(target);
            updateTelegramBackButton();
            updateCloudUpButton();
        }

        async function runWorkAction(title, action) {
            try {
                await action();
            } catch (err) {
                console.error(`${title} ERROR:`, err);
            }
        }

        async function loadRuntimeData() {
            if (DEV_MODE) {
                return {
                    me: {
                        ok: true,
                        user: { telegram_id: "999000111", role: "admin", name: "Dev Mode" },
                        subscription: { status: "active", access_until: new Date(Date.now() + 86400000 * 30).toISOString() },
                        features: { cloud_enabled: true },
                    },
                    status: {
                        ok: true,
                        services: {
                            vless: { ok: true, visible_in_app: true },
                            http: { ok: true, visible_in_app: true },
                            mixed: { ok: true, visible_in_app: true },
                            https_mixed: { ok: true, visible_in_app: true },
                        },
                    },
                    vless: {
                        ok: true,
                        host: "dev.local",
                        port: 443,
                        vless_url: "vless://demo",
                        connections: [
                            { label: "Dev-VLESS-1", host: "dev.local", port: 443, vless_url: "vless://demo1" },
                            { label: "Dev-VLESS-2", host: "dev.local", port: 443, vless_url: "vless://demo2" },
                        ],
                    },
                    http: {
                        ok: true,
                        host: "dev.local",
                        port: 8080,
                        urls: ["http://demo"],
                        connections: [
                            { label: "Dev-HTTP-1", host: "dev.local", port: 8080, urls: ["http://demo-http-1"] },
                        ],
                    },
                    mixed: {
                        ok: true,
                        host: "dev.local",
                        port: 8443,
                        username: "DEV_USER",
                        password: "DEV_PASS",
                        urls: ["socks5://demo"],
                        connections: [
                            { label: "Dev-Mixed-1", host: "dev.local", port: 8443, username: "CAR011NA", password: "yLO06l4AFM", urls: ["socks5://demo1", "http://demo1"] },
                            { label: "Dev-Mixed-2", host: "dev.local", port: 8443, username: "BYTEARC", password: "pass_2", urls: ["socks5://demo2", "http://demo2"] },
                        ],
                    },
                };
            }

            const [me, status, vless, http, mixed] = await Promise.all([
                fetchJson(meUrl, false),
                fetchJson(statusUrl, false),
                fetchJson(vpnConfigUrl, true),
                fetchJson(vpnHttpUrl, true),
                fetchJson(vpnMixedUrl, true),
            ]);
            return { me, status, vless, http, mixed };
        }

        const statusSteps = [
            { text: "Проверяем сервер…", glow: "rgba(55, 224, 255, 0.55)" },
            { text: "Загружаем подключения…", glow: "rgba(79, 123, 255, 0.55)" },
            { text: "Готовим данные…", glow: "rgba(168, 85, 247, 0.55)" },
        ];
        let statusIndex = 0;

        function cycleStatus() {
            statusLabel.classList.add("fade-out");
            setTimeout(() => {
                statusIndex = (statusIndex + 1) % statusSteps.length;
                const step = statusSteps[statusIndex];
                statusLabel.textContent = step.text;
                pulseScene?.style.setProperty("--glow-color", step.glow);
                statusLabel.classList.remove("fade-out");
            }, 160);
        }

        const CYCLE_MS = 4800; // удлинённый цикл для тестов (было 2400)
        setInterval(cycleStatus, CYCLE_MS);
        pulseScene?.style.setProperty("--glow-color", statusSteps[0].glow);

        async function validateUser() {
            if (DEV_MODE) {
                const fakeUser = {
                    id: 0,
                    username: "dev_user",
                    first_name: "Dev",
                    last_name: "Mode",
                };
                return { ok: true, user: fakeUser };
            }

            const initData = window.Telegram?.WebApp?.initData;
            console.log("initData present:", Boolean(initData));
            if (!initData) {
                throw new Error("Не обнаружены данные Telegram Web App. Запустите мини‑приложение через Telegram.");
            }

            console.log("sending /api/tg/auth");
            const response = await fetch(authUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                credentials: "same-origin",
                body: JSON.stringify({ initData }),
            });

            let payload;
            try {
                payload = await response.json();
            } catch (e) {
                const raw = await response.text();
                console.error("Auth raw response:", raw);
                throw new Error("Сервер вернул не-JSON: " + raw.slice(0, 120));
            }

            if (!response.ok || !payload.ok) {
                throw new Error(payload.error || "Телеграм не подтвердил данные пользователя.");
            }

            csrfToken = typeof payload?.csrf_token === "string" ? payload.csrf_token : "";
            if (!csrfToken) {
                throw new Error("Сервер не вернул CSRF token.");
            }
            return payload;
        }

        async function init() {
            console.log("Init start");
            try {
                window.Telegram?.WebApp?.ready?.();
                ensureSafeViewportMode();
                syncBackNavigationMode();
                setTopbarVisibility(false);
                await loadNavSecondPreference();
                await loadVlessGuidePreference();
                const payload = await validateUser();
                console.log("Auth ok", payload.user);
                const runtime = await loadRuntimeData();
                renderDashboard(runtime);
                const delay = payload?.show_long_intro ? 2400 : 400;
                await wait(delay);
                await showApp(payload.user?.first_name || payload.user?.username);
            } catch (err) {
                console.error("Auth failed", err);
                showError(err.message);
            } finally {
                // страхуемся от зависания лоадера
                loading.classList.add("hidden");
                mainEl.classList.remove("hidden");
            }
        }

        if (document.readyState === "loading") {
            window.addEventListener("DOMContentLoaded", init);
        } else {
            init();
        }

        // bottom nav (простое переключение экранов)
        navButtons.forEach((btn) =>
            btn.addEventListener("click", () => {
                switchScreen(btn.dataset.screen);
            })
        );
        settingsNavSecondSelectEl?.addEventListener("change", () => {
            const nextValue = normalizeNavSecondItemKey(settingsNavSecondSelectEl.value);
            saveNavSecondPreference(nextValue).catch((err) => {
                console.error("save nav second preference error:", err);
            });
        });
        screenMenuContextPillEl?.addEventListener("click", () => {
            runScreenMenuContextAction().catch((err) => {
                console.error("screen menu context action click error:", err);
            });
        });
        screenMenuContextPillEl?.addEventListener("keydown", (event) => {
            if (event.key !== "Enter" && event.key !== " ") return;
            event.preventDefault();
            runScreenMenuContextAction().catch((err) => {
                console.error("screen menu context action key error:", err);
            });
        });
        workPageContextPillEl?.addEventListener("click", () => {
            runWorkPageContextAction().catch((err) => {
                console.error("work page context action click error:", err);
            });
        });
        workPageContextPillEl?.addEventListener("keydown", (event) => {
            if (event.key !== "Enter" && event.key !== " ") return;
            event.preventDefault();
            runWorkPageContextAction().catch((err) => {
                console.error("work page context action key error:", err);
            });
        });

        connectionProtocolButtons.forEach((btn) =>
            btn.addEventListener("click", () => {
                const protocol = btn.dataset.connectionProtocol;
                if (!protocol) return;
                openConnectionsDetail(protocol);
            })
        );

        connectionsBackBtnEl?.addEventListener("click", () => {
            openConnectionsMenu();
        });

        cloudUpBtnEl?.addEventListener("click", () => {
            loadCloudPath(cloudParentPath(cloudState.path)).catch((err) => {
                console.error("cloud up error:", err);
                setCloudStatus(err.message || "Не удалось открыть родительскую папку", "error");
            });
        });

        cloudNewFolderBtnEl?.addEventListener("click", async () => {
            await createCloudFolder();
        });

        cloudUploadInputEl?.addEventListener("change", async () => {
            const files = cloudUploadInputEl?.files;
            if (!files || !files.length) return;
            try {
                await uploadCloudFiles(files);
            } finally {
                cloudUploadInputEl.value = "";
            }
        });

        cloudPreviewCloseBtnEl?.addEventListener("click", () => {
            closeCloudPreview();
        });
        workInboundDetailToggleBtnEl?.addEventListener("click", async () => {
            const panelId = workInboundDetailToggleBtnEl.dataset.panelInboundId;
            const nextVisible = workInboundDetailToggleBtnEl.dataset.nextVisible;
            await toggleWorkInboundVisibility(panelId, nextVisible);
        });
        workInboundDetailAddClientBtnEl?.addEventListener("click", async () => {
            await runWorkAction("Add Inbound Client", async () => {
                try {
                    await createWorkInboundClient();
                } catch (err) {
                    setInboundDetailAddStatus(err?.message || "Не удалось добавить клиента", "error");
                    throw err;
                }
            });
        });
        workInboundDetailNewClientLabelEl?.addEventListener("keydown", async (event) => {
            if (event.key !== "Enter") return;
            event.preventDefault();
            workInboundDetailAddClientBtnEl?.click();
        });
        vlessGuideHideBtnEl?.addEventListener("click", () => {
            closeVlessGuide();
        });
        vlessGuideHideCheckboxEl?.addEventListener("change", async () => {
            try {
                await saveVlessGuidePreference(Boolean(vlessGuideHideCheckboxEl.checked));
            } catch (err) {
                console.error("save vless guide preference error:", err);
            }
        });
        vlessGuideCardEl?.addEventListener("click", (event) => {
            event.stopPropagation();
        });
        vlessGuideOverlayEl?.addEventListener("click", (event) => {
            if (event.target === vlessGuideOverlayEl) {
                closeVlessGuide();
            }
        });
        cloudPreviewCardEl?.addEventListener("click", (event) => {
            event.stopPropagation();
        });
        cloudPreviewOverlayEl?.addEventListener("click", (event) => {
            if (event.target === cloudPreviewOverlayEl) {
                closeCloudPreview();
            }
        });
        document.addEventListener("keydown", (event) => {
            if (event.key !== "Escape") return;
            if (getActiveScreenId() === "screen-work" && getActiveWorkPageId() === "work-inbound-detail-page") {
                switchWorkPage("work-panel-detail-page");
                return;
            }
            if (getActiveScreenId() === "screen-work" && getActiveWorkPageId() === "work-panel-detail-page") {
                switchWorkPage("work-panels-page");
                return;
            }
            if (getActiveScreenId() === "screen-work" && getActiveWorkPageId() === "work-panel-create-page") {
                switchWorkPage("work-panels-page");
                return;
            }
            if (cloudPreviewOverlayEl && !cloudPreviewOverlayEl.classList.contains("hidden")) {
                closeCloudPreview();
                return;
            }
            if (vlessGuideOverlayEl && !vlessGuideOverlayEl.classList.contains("hidden")) {
                closeVlessGuide();
            }
        });

        workNavButtons.forEach((btn) =>
            btn.addEventListener("click", () => {
                switchWorkPage(btn.dataset.workNav || "work-menu-page");
            })
        );

        workBackButtons.forEach((btn) =>
            btn.addEventListener("click", () => {
                switchWorkPage(btn.dataset.workBack || "work-menu-page");
            })
        );

        profileIdToggleEl?.addEventListener("click", () => {
            showFullTelegramId = !showFullTelegramId;
            renderTelegramId();
        });

        workClientSearchEl?.addEventListener("input", () => {
            renderWorkClientCards();
        });

        profileReferralApplyEl?.addEventListener("click", async () => {
            const code = String(profileReferralCodeEl?.value || "").trim();
            if (!code) {
                profileReferralStatusTitleEl.textContent = "Ошибка";
                profileReferralStatusEl.textContent = "Введите код";
                profileReferralStatusCardEl?.classList.remove("hidden");
                return;
            }
            profileReferralApplyEl.disabled = true;
            const baseText = profileReferralApplyEl.textContent;
            profileReferralApplyEl.textContent = "Проверяем...";
            try {
                await postJson(`${window.location.origin}/api/verify`, { code });
                profileReferralStatusTitleEl.textContent = "Готово";
                profileReferralStatusEl.textContent = "Доступ расширен";
                profileReferralStatusCardEl?.classList.remove("hidden");
                const runtime = await loadRuntimeData();
                renderDashboard(runtime);
                profileReferralCodeEl.value = "";
            } catch (err) {
                profileReferralStatusTitleEl.textContent = "Ошибка";
                profileReferralStatusEl.textContent = err?.message || "Код неверный";
                profileReferralStatusCardEl?.classList.remove("hidden");
            } finally {
                profileReferralApplyEl.disabled = false;
                profileReferralApplyEl.textContent = baseText;
            }
        });

        workSettingsRefreshBtnEl?.addEventListener("click", async () => {
            try {
                await loadWorkSystemSettings();
                setWorkSettingsStatus("Настройки обновлены", "success");
            } catch (err) {
                console.error("refresh system settings error:", err);
                setWorkSettingsStatus(err?.message || "Не удалось обновить настройки", "error");
            }
        });

        workSettingsSaveBtnEl?.addEventListener("click", async () => {
            try {
                await saveWorkSystemSettings();
                setWorkSettingsStatus("Настройки сохранены", "success");
            } catch (err) {
                console.error("save system settings error:", err);
                setWorkSettingsStatus(err?.message || "Не удалось сохранить настройки", "error");
            }
        });

        workPanelTestBtnEl?.addEventListener("click", async () => {
            try {
                setWorkPanelStatus("Проверяем подключение...");
                const result = await testWorkPanelConnection();
                const inboundsCount = Number(result?.result?.inbounds_count || 0);
                setWorkPanelStatus(`Подключение успешно. inbound: ${inboundsCount}`, "success");
            } catch (err) {
                console.error("test panel connection error:", err);
                setWorkPanelStatus(err?.message || "Не удалось проверить подключение", "error");
            }
        });

        workPanelSaveBtnEl?.addEventListener("click", async () => {
            try {
                setWorkPanelStatus("Сохраняем панель...");
                await saveWorkPanel();
                setWorkPanelStatus("Панель сохранена", "success");
            } catch (err) {
                console.error("save panel error:", err);
                setWorkPanelStatus(err?.message || "Не удалось сохранить панель", "error");
            }
        });

        workPanelDetailActivateBtnEl?.addEventListener("click", async () => {
            const panelId = String(workPanelDetailActivateBtnEl.dataset.panelId || "").trim();
            if (!panelId) return;
            try {
                const panel = findWorkPanelById(panelId);
                if (!panel) {
                    throw new Error("Панель не найдена");
                }
                setWorkPanelDetailStatus(panel?.is_active ? "Деактивируем панель..." : "Активируем панель...");
                await toggleWorkPanelActive(panel);
                setWorkPanelDetailStatus("Статус панели обновлен", "success");
            } catch (err) {
                console.error("toggle panel active error:", err);
                setWorkPanelDetailStatus(err?.message || "Не удалось изменить статус панели", "error");
            }
        });

        workPanelDetailSyncBtnEl?.addEventListener("click", async () => {
            const panelId = String(workPanelDetailSyncBtnEl.dataset.panelId || "").trim();
            if (!panelId) return;
            try {
                const panel = findWorkPanelById(panelId);
                if (!panel) {
                    throw new Error("Панель не найдена");
                }
                setWorkPanelDetailStatus("Синхронизируем inbound...");
                await syncWorkPanel(panel);
                setWorkPanelDetailStatus("Синхронизация завершена", "success");
            } catch (err) {
                console.error("sync panel error:", err);
                setWorkPanelDetailStatus(err?.message || "Не удалось синхронизировать панель", "error");
            }
        });

        workPanelDetailAccessBtnEl?.addEventListener("click", () => {
            toggleWorkPanelAccessSection(null);
        });

        workPanelDetailTestBtnEl?.addEventListener("click", async () => {
            const panelId = String(workPanelDetailTestBtnEl.dataset.panelId || "").trim();
            if (!panelId) return;
            try {
                setWorkPanelDetailStatus("Проверяем доступ...");
                const result = await testWorkPanelDetailConnection(panelId);
                const inboundsCount = Number(result?.result?.inbounds_count || 0);
                setWorkPanelDetailStatus(`Доступ подтвержден. inbound: ${inboundsCount}`, "success");
            } catch (err) {
                console.error("test panel detail connection error:", err);
                setWorkPanelDetailStatus(err?.message || "Не удалось проверить доступ", "error");
            }
        });

        workPanelDetailSaveBtnEl?.addEventListener("click", async () => {
            const panelId = String(workPanelDetailSaveBtnEl.dataset.panelId || "").trim();
            if (!panelId) return;
            try {
                setWorkPanelDetailStatus("Сохраняем настройки доступа...");
                await saveWorkPanelDetailAccess(panelId);
                setWorkPanelDetailStatus("Настройки доступа сохранены", "success");
            } catch (err) {
                console.error("save panel detail access error:", err);
                setWorkPanelDetailStatus(err?.message || "Не удалось сохранить настройки доступа", "error");
            }
        });

        workPanelDetailDeleteBtnEl?.addEventListener("click", async () => {
            const panelId = String(workPanelDetailDeleteBtnEl.dataset.panelId || "").trim();
            if (!panelId) return;
            try {
                await deleteWorkPanel(panelId);
            } catch (err) {
                console.error("delete panel error:", err);
                setWorkPanelDetailStatus(err?.message || "Не удалось удалить панель", "error");
            }
        });

        workRefreshInboundClientsBtnEl?.addEventListener("click", async () => {
            await runWorkAction("Refresh Inbound Clients", async () => {
                return refreshInboundClientsFromPanel();
            });
        });

        workInboundSelectEl?.addEventListener("change", async () => {
            workState.clients = [];
            fillSelect(workClientSelectEl, [], () => "", () => "", "Select client from inbound");
            if (!workInboundSelectEl?.value) {
                return;
            }
            try {
                await loadInboundClients(workInboundSelectEl.value);
            } catch (err) {
                console.error("load inbound clients error:", err);
            }
        });

        workPendingInboundSelectEl?.addEventListener("change", async () => {
            workState.pendingClients = [];
            fillSelect(workPendingClientSelectEl, [], () => "", () => "", "Select client from inbound");
            if (!workPendingInboundSelectEl?.value) {
                return;
            }
            try {
                await loadPendingInboundClients(workPendingInboundSelectEl.value);
            } catch (err) {
                console.error("load pending inbound clients error:", err);
            }
        });

        workPendingTelegramIdEl?.addEventListener("change", async () => {
            try {
                await Promise.all([
                    loadPendingBindings(workPendingTelegramIdEl.value),
                    loadPendingSubscriptionOverview(workPendingTelegramIdEl.value),
                ]);
            } catch (err) {
                console.error("load pending data error:", err);
            }
        });

        workPendingSubStatusSelectEl?.addEventListener("change", () => {
            renderPendingSubscriptionControls(workState.pendingOverview?.subscription || null, { preserveDate: true });
        });

        workPendingSubSaveBtnEl?.addEventListener("click", async () => {
            await runWorkAction("Save Pending Subscription", async () => {
                const telegramId = String(workPendingTelegramIdEl?.value || "").trim();
                if (!isValidTelegramId(telegramId)) {
                    setPendingSubscriptionStatus("Укажи корректный Telegram ID.", "error");
                    throw new Error("Enter valid Telegram ID");
                }

                const hasSubscription = Boolean(workState.pendingOverview?.subscription);
                const selectedStatus = normalizeSubscriptionStatus(workPendingSubStatusSelectEl?.value || "active");
                const payload = {
                    telegram_id: telegramId,
                    status: selectedStatus || "active",
                    price_amount: workPendingSubPriceInputEl?.value?.trim() || null,
                    connections_limit: workPendingSubLimitInputEl?.value?.trim() || null,
                };

                if (selectedStatus === "lifetime") {
                    payload.access_until = null;
                } else {
                    const rawDate = String(workPendingSubCreateDateEl?.value || "").trim();
                    try {
                        if (rawDate) {
                            payload.access_until = validateSubscriptionDateValue(rawDate);
                        } else if (!hasSubscription) {
                            payload.access_until = validateSubscriptionDateValue(rawDate);
                        }
                    } catch (err) {
                        setPendingSubscriptionStatus(err?.message || "Невалидная дата подписки.", "error");
                        throw err;
                    }
                }

                let result;
                try {
                    result = await postJson(adminUserSubscriptionByTelegramUrl, payload);
                } catch (err) {
                    setPendingSubscriptionStatus(err?.message || "Не удалось сохранить подписку.", "error");
                    throw err;
                }
                renderPendingSubscriptionOverview(result?.overview || null);
                upsertWorkUserFromOverview(result?.overview || null);
                setPendingSubscriptionStatus(
                    result?.created_user
                        ? "Подписка сохранена. Пользователь создан."
                        : "Подписка сохранена.",
                    "success"
                );
                return result;
            });
        });

        workBindBtnEl?.addEventListener("click", async () => {
            await runWorkAction("Bind Client", async () => {
                const userId = workState.selectedUserId;
                if (!userId) {
                    throw new Error("Open client card first");
                }
                const { panelInboundRefId, inbound, client } = resolveInboundClientSelection(
                    workInboundSelectEl,
                    workClientSelectEl,
                    workState.clients,
                    "Select inbound and client"
                );

                const payload = {
                    user_id: Number(userId),
                    panel_inbound_ref_id: panelInboundRefId,
                    client_identifier: client.identifier,
                    protocol: (inbound.protocol || client.protocol || "").toLowerCase(),
                    label: client.label,
                    secret: client.secret,
                    sub_id: client.sub_id,
                };

                const result = await postJson(adminBindClientUrl, payload);
                await loadSelectedUserBindings();
                await loadSelectedUserOverview();
                return result;
            });
        });

        workPendingAddBtnEl?.addEventListener("click", async () => {
            await runWorkAction("Add Pending Binding", async () => {
                const telegramId = String(workPendingTelegramIdEl?.value || "").trim();
                if (!isValidTelegramId(telegramId)) {
                    throw new Error("Enter valid Telegram ID");
                }

                const { panelInboundRefId, inbound, client } = resolveInboundClientSelection(
                    workPendingInboundSelectEl,
                    workPendingClientSelectEl,
                    workState.pendingClients,
                    "Select inbound and client for pending"
                );

                const payload = {
                    telegram_id: telegramId,
                    panel_inbound_ref_id: panelInboundRefId,
                    client_identifier: client.identifier,
                    protocol: (inbound.protocol || client.protocol || "").toLowerCase(),
                    label: client.label,
                    secret: client.secret,
                    sub_id: client.sub_id,
                };

                const result = await postJson(adminPendingBindingsUrl, payload);
                await loadPendingBindings(telegramId);
                return result;
            });
        });

        workSubSaveBtnEl?.addEventListener("click", async () => {
            await runWorkAction("Save Subscription", async () => {
                if (!workState.selectedUserId) {
                    throw new Error("Сначала открой карточку клиента");
                }

                const currentSubscription = workState.overview?.subscription || null;
                const creatingSubscription = !currentSubscription;
                const selectedStatus = normalizeSubscriptionStatus(workSubStatusSelectEl?.value || "active");
                const switchingLifetimeToActive =
                    isSubscriptionLifetime(currentSubscription) && selectedStatus === "active";
                const payload = {
                    status: selectedStatus || "active",
                    price_amount: workSubPriceInputEl?.value?.trim() || null,
                    connections_limit: workSubLimitInputEl?.value?.trim() || null,
                };
                if (selectedStatus === "lifetime") {
                    payload.access_until = null;
                } else if (creatingSubscription || switchingLifetimeToActive) {
                    payload.access_until = validateSubscriptionDateValue(workSubCreateDateEl?.value);
                }
                const result = await postJson(adminUserSubscriptionUrl(workState.selectedUserId), payload);
                renderWorkClientOverview(result?.overview || null);
                return result;
            });
        });
        workSubExtendBtnEl?.addEventListener("click", async () => {
            await runWorkAction("Extend Subscription", async () => {
                if (!workState.selectedUserId) {
                    throw new Error("Сначала открой карточку клиента");
                }
                const hasSubscription = Boolean(workState.overview?.subscription);
                if (!hasSubscription) {
                    const selectedStatus = normalizeSubscriptionStatus(workSubStatusSelectEl?.value || "active");
                    const payload =
                        selectedStatus === "lifetime"
                            ? { status: "lifetime", access_until: null }
                            : {
                                  status: "active",
                                  access_until: validateSubscriptionDateValue(workSubCreateDateEl?.value),
                              };
                    const result = await postJson(adminUserSubscriptionUrl(workState.selectedUserId), payload);
                    renderWorkClientOverview(result?.overview || null);
                    return result;
                }
                if (isSubscriptionLifetime(workState.overview?.subscription)) {
                    throw new Error("Бессрочную подписку не нужно продлевать");
                }
                const months = Number(workSubExtendRangeEl?.value || 0);
                if (!Number.isInteger(months) || months <= 0) {
                    throw new Error("Выбери срок продления");
                }
                const result = await postJson(adminUserSubscriptionUrl(workState.selectedUserId), {
                    extend_months: months,
                });
                renderWorkClientOverview(result?.overview || null);
                return result;
            });
        });

        workSubExtendRangeEl?.addEventListener("input", () => {
            renderWorkSubExtendValue();
        });
        workSubStatusSelectEl?.addEventListener("change", () => {
            renderWorkSubscriptionControls(workState.overview?.subscription || null);
        });
        renderWorkSubExtendValue();
        updateCloudPageContext(cloudState.path);
        updateCloudUpButton();
