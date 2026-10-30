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
        const userBottomNavEl = document.getElementById("user-bottom-nav");
        const adminBottomNavEl = document.getElementById("admin-bottom-nav");
        const adminPageButtons = document.querySelectorAll("[data-admin-page]");
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
        const adminKnownUsersUrl = `${adminUsersUrl}/known`;
        const adminGroupsUrl = `${window.location.origin}/api/groups`;
        const adminInboundsUrl = `${window.location.origin}/api/admin/inbounds`;
        const adminSyncInboundsUrl = `${window.location.origin}/api/admin/sync-inbounds`;
        const adminBindClientUrl = `${window.location.origin}/api/admin/bind-client`;
        const adminUnbindClientUrl = `${window.location.origin}/api/admin/unbind-client`;
        const adminPanelClientsUrl = `${window.location.origin}/api/admin/panel-clients`;
        const adminUserPanelClientUrl = (userId) => `${window.location.origin}/api/admin/users/${userId}/panel-client`;
        const adminInboundVisibilityUrl = (panelInboundId) => `${window.location.origin}/api/admin/inbounds/${panelInboundId}/visibility`;
        const adminInboundClientsUrl = (panelInboundId) => `${window.location.origin}/api/admin/inbounds/${panelInboundId}/clients`;
        const adminUserBindingsUrl = (userId) => `${window.location.origin}/api/admin/users/${userId}/bindings`;
        const adminUserOverviewUrl = (userId) => `${window.location.origin}/api/admin/users/${userId}/overview`;
        const adminUserRoleUrl = (userId) => `${window.location.origin}/api/admin/users/${userId}/role`;
        const adminUserSubscriptionUrl = (userId) => `${window.location.origin}/api/admin/users/${userId}/subscription`;
        const adminUserOverviewByTelegramUrl = (telegramId) =>
            `${window.location.origin}/api/admin/users/by-telegram/${encodeURIComponent(telegramId)}/overview`;
        const adminUserSubscriptionByTelegramUrl = `${window.location.origin}/api/admin/users/by-telegram/subscription`;
        const adminSettingsUrl = `${window.location.origin}/api/admin/settings`;
        const adminSettingUrl = (settingKey) => `${adminSettingsUrl}/${encodeURIComponent(settingKey)}`;
        const adminPanelsUrl = `${window.location.origin}/api/admin/panels`;
        const adminBroadcastsUrl = `${window.location.origin}/api/admin/broadcasts`;
        const adminApplicationsUrl = `${window.location.origin}/api/admin/applications`;
        const adminFinanceSummaryUrl = `${window.location.origin}/api/admin/finance/summary`;
        const adminFinanceExpensesUrl = `${window.location.origin}/api/admin/finance/expenses`;
        const adminPanelsTestUrl = `${window.location.origin}/api/admin/panels/test-connection`;
        const adminPanelUpdateUrl = (panelId) => `${adminPanelsUrl}/${encodeURIComponent(panelId)}`;
        const adminPanelMetricsUrl = (panelId) => `${adminPanelsUrl}/${encodeURIComponent(panelId)}/metrics`;
        const adminPanelActionUrl = (panelId, action) => `${adminPanelsUrl}/${encodeURIComponent(panelId)}/${action}`;
        const cloudListUrl = `${window.location.origin}/api/cloud/list`;
        const cloudMkdirUrl = `${window.location.origin}/api/cloud/mkdir`;
        const cloudUploadUrl = `${window.location.origin}/api/cloud/upload`;
        const cloudDeleteNodeUrl = (nodeId) => `${window.location.origin}/api/cloud/nodes/${nodeId}`;
        const cloudDownloadFileUrl = (fileId) => `${window.location.origin}/api/cloud/files/${fileId}/download`;
        const subscriptionOptionsUrl = `${window.location.origin}/api/subscription/options`;
        const subscriptionDraftUrl = `${window.location.origin}/api/subscription/draft`;
        const subscriptionConfirmUrl = `${window.location.origin}/api/subscription/confirm`;
        const homeServerSub = document.getElementById("home-server-sub");
        const homeSubTitle = document.getElementById("home-sub-title");
        const homeSubSub = document.getElementById("home-sub-sub");
        const homeSubRight = document.getElementById("home-sub-right");
        const homeCloudBtnEl = document.getElementById("home-cloud-btn");
        const homeServerCardEl = document.getElementById("home-server-card");
        const homeSubscriptionCardEl = document.getElementById("home-subscription-card");
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
        const subscriptionBuilderEl = document.getElementById("subscription-builder");
        const subscriptionBuilderSubEl = document.getElementById("subscription-builder-sub");
        const subscriptionRegionListEl = document.getElementById("subscription-region-list");
        const subscriptionTrafficListEl = document.getElementById("subscription-traffic-list");
        const subscriptionCloudGbEl = document.getElementById("subscription-cloud-gb");
        const subscriptionPriceValueEl = document.getElementById("subscription-price-value");
        const subscriptionBuilderStatusEl = document.getElementById("subscription-builder-status");
        const subscriptionDraftBtnEl = document.getElementById("subscription-draft-btn");
        const subscriptionConfirmBtnEl = document.getElementById("subscription-confirm-btn");
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
        const workPanelTokenEl = document.getElementById("work-panel-token");
        const workPanelTestBtnEl = document.getElementById("work-panel-test-btn");
        const workPanelSaveBtnEl = document.getElementById("work-panel-save-btn");
        const workPanelStatusEl = document.getElementById("work-panel-status");
        const workPanelDetailTitleEl = document.getElementById("work-panel-detail-title");
        const workPanelDetailSummaryEl = document.getElementById("work-panel-detail-summary");
        const workPanelDetailActivateBtnEl = document.getElementById("work-panel-detail-activate-btn");
        const workPanelDetailSyncBtnEl = document.getElementById("work-panel-detail-sync-btn");
        const workPanelDetailAccessBtnEl = document.getElementById("work-panel-detail-access-btn");
        const workPanelDetailAccessWrapEl = document.getElementById("work-panel-detail-access-wrap");
        const workPanelDetailBaseUrlEl = document.getElementById("work-panel-detail-base-url");
        const workPanelDetailUsernameEl = document.getElementById("work-panel-detail-username");
        const workPanelDetailPasswordEl = document.getElementById("work-panel-detail-password");
        const workPanelDetailTokenEl = document.getElementById("work-panel-detail-token");
        const workPanelDetailTestBtnEl = document.getElementById("work-panel-detail-test-btn");
        const workPanelDetailSaveBtnEl = document.getElementById("work-panel-detail-save-btn");
        const workPanelDetailDeleteBtnEl = document.getElementById("work-panel-detail-delete-btn");
        const workPanelDetailStatusEl = document.getElementById("work-panel-detail-status");
        const workPanelDetailInboundsListEl = document.getElementById("work-panel-detail-inbounds-list");
        const workPanelDetailInboundsBtnEl = document.getElementById("work-panel-detail-inbounds-btn");
        const workPanelDetailClientsBtnEl = document.getElementById("work-panel-detail-clients-btn");
        const workPanelClientsListEl = document.getElementById("work-panel-clients-list");
        const workPanelClientsStatusEl = document.getElementById("work-panel-clients-status");
        const workPanelAccessOverlayEl = document.getElementById("work-panel-access-overlay");
        const workPanelAccessCloseEl = document.getElementById("work-panel-access-close");
        const workPanelAccessStatusEl = document.getElementById("work-panel-access-status");
        const workClientActionsBtnEl = document.getElementById("work-client-actions-btn");
        const workClientExtendBtnEl = document.getElementById("work-client-extend-btn");
        const workClientActionsOverlayEl = document.getElementById("work-client-actions-overlay");
        const workClientActionsCloseEl = document.getElementById("work-client-actions-close");
        const workClientExtendOverlayEl = document.getElementById("work-client-extend-overlay");
        const workClientExtendCloseEl = document.getElementById("work-client-extend-close");
        const workClientActionsPopupStatusEl = document.getElementById("work-client-actions-status");
        const workClientExtendPopupStatusEl = document.getElementById("work-client-extend-status");
        const workClientStatusChipsEl = document.getElementById("work-client-status-chips");
        const workClientRemoveMemberBtnEl = document.getElementById("work-client-remove-member-btn");
        const workClientMemberNoteEl = document.getElementById("work-client-member-note");
        const workClientGroupBtnEl = document.getElementById("work-client-group-btn");
        const workClientGroupListEl = document.getElementById("work-client-group-list");
        const workClientExtendLifetimeNoteEl = document.getElementById("work-client-extend-lifetime-note");
        const workSubDateBtnEl = document.getElementById("work-sub-date-btn");
        const workClientActionsRowEl = document.getElementById("work-client-actions-row");
        const workClientNavRowEl = document.getElementById("work-client-nav-row");
        const workClientSubscriptionsBtnEl = document.getElementById("work-client-subscriptions-btn");
        const workClientToAdminBtnEl = document.getElementById("work-client-to-admin-btn");
        const workSubTypeSaveBtnEl = document.getElementById("work-sub-type-save-btn");
        const workSubCurrentGroupEl = document.getElementById("work-sub-current-group");
        const workMemberNotesEl = document.getElementById("work-member-notes");
        const workClientIdentityBtnEl = document.getElementById("work-client-identity-btn");
        const workClientIdentityOverlayEl = document.getElementById("work-client-identity-overlay");
        const workClientIdentityCloseEl = document.getElementById("work-client-identity-close");
        const workClientIdentityNameEl = document.getElementById("work-client-identity-name");
        const workClientIdentityUsernameEl = document.getElementById("work-client-identity-username");
        const workClientIdentityTelegramIdEl = document.getElementById("work-client-identity-telegram-id");
        const workClientIdentitySaveEl = document.getElementById("work-client-identity-save");
        const workClientIdentityDeleteEl = document.getElementById("work-client-identity-delete");
        const workClientIdentityStatusEl = document.getElementById("work-client-identity-status");
        const workClientsFiltersOverlayEl = document.getElementById("work-clients-filters-overlay");
        const workClientsFiltersCloseEl = document.getElementById("work-clients-filters-close");
        const workFilterPriceMinEl = document.getElementById("work-filter-price-min");
        const workFilterPriceMaxEl = document.getElementById("work-filter-price-max");
        const workFilterServersEl = document.getElementById("work-filter-servers");
        const workFilterResetEl = document.getElementById("work-filter-reset");
        const workFilterApplyEl = document.getElementById("work-filter-apply");
        const workClientFilterSummaryEl = document.getElementById("work-client-filter-summary");
        const workClientFilterSummaryTextEl = document.getElementById("work-client-filter-summary-text");
        const workClientFilterSummaryResetEl = document.getElementById("work-client-filter-summary-reset");
        // Фильтры списка клиентов: внутри категории - «или», между категориями - «и».
        const newClientFilters = () => ({
            types: new Set(), days: new Set(), payment: new Set(), status: new Set(), servers: new Set(),
            priceMin: "", priceMax: "",
        });
        const clientFilters = newClientFilters();
        const recipientFilters = newClientFilters();  // свои фильтры на экране выбора получателей
        // Какие страницы умеют фильтры (долгое нажатие на капсулу) и как перерисовать их список.
        const filterContexts = {
            "work-clients-page": { filters: clientFilters, rerender: () => renderWorkClientCards() },
            "work-broadcast-recipients-page": { filters: recipientFilters, rerender: () => renderRecipientList() },
        };
        let activeFilterPage = "work-clients-page";
        const activeFilters = () => filterContexts[activeFilterPage].filters;
        const workSelectionBarEl = document.getElementById("work-selection-bar");
        const workSelectionAllEl = document.getElementById("work-selection-all");
        const workSelectionClearEl = document.getElementById("work-selection-clear");
        const workSelectionConfirmEl = document.getElementById("work-selection-confirm");
        const workRecipientListEl = document.getElementById("work-recipient-list");
        const workRecipientSearchEl = document.getElementById("work-recipient-search");
        const workRecipientFilterSummaryEl = document.getElementById("work-recipient-filter-summary");
        const workRecipientFilterSummaryTextEl = document.getElementById("work-recipient-filter-summary-text");
        const workRecipientFilterSummaryResetEl = document.getElementById("work-recipient-filter-summary-reset");
        const workAdminNotificationsBtnEl = document.getElementById("work-admin-notifications-btn");
        const workAdminFinanceBtnEl = document.getElementById("work-admin-finance-btn");
        const workBroadcastTypesEl = document.getElementById("work-broadcast-types");
        const workBroadcastSummaryEl = document.getElementById("work-broadcast-recipients-summary");
        const workBroadcastPickEl = document.getElementById("work-broadcast-pick");
        const workBroadcastTextEl = document.getElementById("work-broadcast-text");
        const workBroadcastSendEl = document.getElementById("work-broadcast-send");
        const workBroadcastStatusEl = document.getElementById("work-broadcast-status");
        const workBroadcastResultEl = document.getElementById("work-broadcast-result");
        const workBroadcastResultTextEl = document.getElementById("work-broadcast-result-text");
        const workBroadcastResultListEl = document.getElementById("work-broadcast-result-list");
        const workCenterModalEl = document.getElementById("work-center-modal");
        const workCenterModalTitleEl = document.getElementById("work-center-modal-title");
        const workCenterModalTextEl = document.getElementById("work-center-modal-text");
        const workCenterModalListEl = document.getElementById("work-center-modal-list");
        const workCenterModalActionsEl = document.getElementById("work-center-modal-actions");
        const workCenterModalInputEl = document.getElementById("work-center-modal-input");
        const workAdminApplicationsBtnEl = document.getElementById("work-admin-applications-btn");
        const workAdminApplicationsLabelEl = document.getElementById("work-admin-applications-label");
        const workApplicationsListEl = document.getElementById("work-applications-list");
        const workApplicationsStatusEl = document.getElementById("work-applications-status");
        const workApplicationsFilterEl = document.getElementById("work-applications-filter");
        const workAppBlockEl = document.getElementById("work-app-block");
        const workAppNameEl = document.getElementById("work-app-name");
        const workAppMetaEl = document.getElementById("work-app-meta");
        const workAppMessageEl = document.getElementById("work-app-message");
        const workAppReplyCardEl = document.getElementById("work-app-reply-card");
        const workAppReplyEl = document.getElementById("work-app-reply");
        const workAppRejectBtnEl = document.getElementById("work-app-reject-btn");
        const workUserWhoCardEl = document.getElementById("work-user-who-card");
        const workUserCreateTitleEl = document.getElementById("work-user-create-title");
        const broadcastState = { type: "", recipientIds: [], selected: new Set(), sending: false };
        const financeState = { summary: null, loading: false };
        // Заявки на регистрацию: список и режим «одобрение» на форме создания пользователя.
        const appsState = { items: [], filter: "open", loading: false };
        const OPEN_APP_STATUSES = ["new", "reviewing"];
        let applicationMode = null;
        let lastCenterModalInput = "";
        const finEl = (id) => document.getElementById(id);
        // Полноэкранные окна: что писать в капсуле сверху, пока они открыты.
        const fullscreenSheetTitles = new Map([
            [workClientActionsOverlayEl, "Действия"],
            [workClientIdentityOverlayEl, "Идентификация"],
            [workClientsFiltersOverlayEl, "Фильтры"],
        ]);
        const workSubTypeChipsEl = document.getElementById("work-sub-type-chips");
        const workSubNotesSaveBtnEl = document.getElementById("work-sub-notes-save-btn");
        const workSubNotesStatusEl = document.getElementById("work-sub-notes-status");
        const workClientGroupStatusEl = document.getElementById("work-client-group-status");
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
        const workUserCreateModeEl = document.getElementById("work-user-create-mode");
        const workUserExistingWrapEl = document.getElementById("work-user-existing-wrap");
        const workUserExistingSelectEl = document.getElementById("work-user-existing-select");
        const workUserIdentityWrapEl = document.getElementById("work-user-identity-wrap");
        const workUserIdentityEl = document.getElementById("work-user-identity");
        const workUserNameEl = document.getElementById("work-user-name");
        const workUserMonthPriceEl = document.getElementById("work-user-month-price");
        const workUserPaymentDateEl = document.getElementById("work-user-payment-date");
        const workUserPaymentDetailsEl = document.getElementById("work-user-payment-details");
        const workUserSubscriptionTypeEl = document.getElementById("work-user-subscription-type");
        const workUserNotesEl = document.getElementById("work-user-notes");
        const workUserBindingsAddEl = document.getElementById("work-user-bindings-add");
        const workUserBindingsListEl = document.getElementById("work-user-bindings-list");
        const workUserMembersCardEl = document.getElementById("work-user-members-card");
        const workUserMembersAddEl = document.getElementById("work-user-members-add");
        const workUserMembersListEl = document.getElementById("work-user-members-list");
        const workUserCreateSubmitEl = document.getElementById("work-user-create-submit");
        const workUserCreateStatusEl = document.getElementById("work-user-create-status");
        const workMemberModeEl = document.getElementById("work-member-mode");
        const workMemberExistingWrapEl = document.getElementById("work-member-existing-wrap");
        const workMemberExistingSelectEl = document.getElementById("work-member-existing-select");
        const workMemberIdentityWrapEl = document.getElementById("work-member-identity-wrap");
        const workMemberIdentityFieldEl = document.getElementById("work-member-identity-field");
        const workMemberIdentityEl = document.getElementById("work-member-identity");
        const workMemberNameEl = document.getElementById("work-member-name");
        const workMemberNameLabelEl = document.getElementById("work-member-name-label");
        const workMemberBindingsAddEl = document.getElementById("work-member-bindings-add");
        const workMemberBindingsListEl = document.getElementById("work-member-bindings-list");
        const workMemberSaveEl = document.getElementById("work-member-save");
        const workMemberStatusEl = document.getElementById("work-member-status");
        const workBindAddBtnEl = document.getElementById("work-bind-add-btn");
        // Экранов "ожидающих привязок" в разметке больше нет; константы нужны, чтобы
        // обработчики ниже (с ?.) не падали ReferenceError и не обрывали скрипт.
        const workPendingTelegramIdEl = document.getElementById("work-pending-telegram-id");
        const workPendingInboundSelectEl = document.getElementById("work-pending-inbound-select");
        const workPendingClientSelectEl = document.getElementById("work-pending-client-select");
        const workPendingAddBtnEl = document.getElementById("work-pending-add-btn");
        const workPendingSubStatusSelectEl = document.getElementById("work-pending-sub-status-select");
        const workPendingSubPriceInputEl = document.getElementById("work-pending-sub-price-input");
        const workPendingSubLimitInputEl = document.getElementById("work-pending-sub-limit-input");
        const workPendingSubCreateDateEl = document.getElementById("work-pending-sub-create-date");
        const workPendingSubSaveBtnEl = document.getElementById("work-pending-sub-save-btn");
        const workPendingSubSaveStatusEl = document.getElementById("work-pending-sub-save-status");
        const workBindStatusEl = document.getElementById("work-bind-status");
        const uiSheetOverlayEl = document.getElementById("ui-sheet-overlay");
        const uiSheetTitleEl = document.getElementById("ui-sheet-title");
        const uiSheetCloseEl = document.getElementById("ui-sheet-close");
        const uiSheetSearchEl = document.getElementById("ui-sheet-search");
        const uiSheetListEl = document.getElementById("ui-sheet-list");
        const workVerifyMenuBtnEl = document.getElementById("work-verify-menu-btn");
        const workVerifyCountEl = document.getElementById("work-verify-count");
        const workVerifyLengthEl = document.getElementById("work-verify-length");
        const workVerifyGenerateEl = document.getElementById("work-verify-generate");
        const workVerifyStatusEl = document.getElementById("work-verify-status");
        const workVerifyListEl = document.getElementById("work-verify-list");
        const workClientPageTitleEl = document.getElementById("work-client-page-title");
        const workClientNameEl = document.getElementById("work-client-name");
        const workClientMetaEl = document.getElementById("work-client-meta");
        const workClientSubStatusEl = document.getElementById("work-client-sub-status");
        const workClientSubUntilEl = document.getElementById("work-client-sub-until");
        const workClientSubPriceEl = document.getElementById("work-client-sub-price");
        const workClientConnectionsAvailableEl = document.getElementById("work-client-connections-available");
        const workClientFreezeBtnEl = document.getElementById("work-client-freeze-btn");
        const workClientManualExtendBtnEl = document.getElementById("work-client-manual-extend-btn");
        const workClientActionStatusEl = document.getElementById("work-client-action-status");
        const workClientRoleSelectEl = document.getElementById("work-client-role-select");
        const workClientRoleSaveBtnEl = document.getElementById("work-client-role-save-btn");
        const workClientRoleStatusEl = document.getElementById("work-client-role-status");
        const workExistingLinksEl = document.getElementById("work-existing-links");
        const workInboundSelectEl = document.getElementById("work-inbound-select");
        const workClientSelectEl = document.getElementById("work-client-select");
        const workRefreshInboundClientsBtnEl = document.getElementById("work-refresh-inbound-clients-btn");
        const workSubStatusSelectEl = document.getElementById("work-sub-status-select");
        const workSubPriceInputEl = document.getElementById("work-sub-price-input");
        const workSubLimitInputEl = document.getElementById("work-sub-limit-input");
        const workSubBillingDayEl = document.getElementById("work-sub-billing-day");
        const workSubBillingDetailsEl = document.getElementById("work-sub-billing-details");
        const workSubNotesEl = document.getElementById("work-sub-notes");
        const workSubscriptionTypeSelectEl = document.getElementById("work-subscription-type-select");
        const workSubGroupWrapEl = document.getElementById("work-sub-group-wrap");
        const workSubGroupSelectEl = document.getElementById("work-sub-group-select");
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
            knownUsers: [],
            groups: [],
            inbounds: [],
            clients: [],
            bindings: [],
            settings: {},
            panels: [],
            selectedUserId: null,
            overview: null,
            selectedInboundPanelId: null,
            selectedPanelId: null,
        };
        let adminOnlyMode = false;
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
        const subscriptionBuilderState = {
            options: null,
            plan: null,
            itemsCatalog: [],
            regions: [],
            trafficOptions: [
                { key: "vless", label: "VLESS" },
                { key: "proxy", label: "Proxy" },
                { key: "mixed", label: "Mixed" },
            ],
            selectedRegions: new Set(),
            trafficType: "vless",
            cloudGb: 0,
            draft: null,
            draftId: null,
            loading: false,
            optionsLoading: false,
            draftTimer: null,
            lastPayloadHash: "",
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
            ["work-user-create-page", "Новый пользователь"],
            ["work-user-member-page", "Участник группы"],
            ["work-verify-page", "Коды подтверждения"],
            ["work-inbounds-page", "Подключения"],
            ["work-inbound-detail-page", "Подключение"],
            ["work-system-settings-page", "Системные настройки"],
            ["work-panels-page", "Панели"],
            ["work-panel-create-page", "Новая панель"],
            ["work-panel-detail-page", "Панель"],
            ["work-panel-inbounds-page", "Подключения"],
            ["work-panel-clients-page", "Клиенты"],
            ["work-admin-page", "Администрирование"],
            ["work-broadcast-page", "Рассылка"],
            ["work-broadcast-recipients-page", "Получатели"],
            ["work-applications-page", "Заявки"],
            ["work-finance-page", "Финансы"],
            ["work-finance-details-page", "Детали"],
            ["work-finance-debtors-page", "Должники"],
            ["work-finance-expenses-page", "Расходы"],
            ["work-client-page", "Клиент"],
            ["work-client-connections-page", "Подписки"],
            ["work-client-group-page", "Группа"],
        ]);
        const menuContextTitleByScreen = new Map([
            ["screen-connections", "Подключения"],
            ["screen-cloud", "Облако"],
            ["screen-work", "Работа"],
            ["screen-profile", "Профиль"],
            ["screen-subscription", "Подписка"],
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
            } else if (screenId === "screen-subscription") {
                title = menuContextTitleByScreen.get("screen-subscription") || "";
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
            if (pageId === "work-user-create-page" && applicationMode) {
                return `Заявка №${applicationMode.id}`;
            }
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
            if (pageId === "work-broadcast-recipients-page") {
                return "refresh-work-clients";
            }
            if (String(pageId).startsWith("work-finance")) {
                return "refresh-work-finance";
            }
            if (pageId === "work-applications-page") {
                return "refresh-work-applications";
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
                || pageId === "work-client-group-page"
            ) {
                return "refresh-work-client";
            }
            return "";
        }

        // Пока открыто полноэкранное окно «Действия», в капсуле пишем только «Действия» (без имени клиента).
        let workContextOverrideTitle = "";

        function updateWorkPageContext(pageId) {
            if (!workPageContextEl || !workPageContextPillEl) return;
            workPageContextPillEl.classList.remove("busy", "filtered");
            if (workContextOverrideTitle) {
                workPageContextEl.dataset.action = "";
                workPageContextEl.classList.remove("clickable");
                workPageContextPillEl.tabIndex = -1;
                workPageContextPillEl.removeAttribute("role");
                workPageContextPillEl.textContent = workContextOverrideTitle;
                workPageContextPillEl.title = workContextOverrideTitle;
                workPageContextEl.classList.remove("hidden");
                return;
            }
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
            // Значка обновления нет: при нажатии капсула становится фиолетовой, пока идёт обновление.
            const displayTitle = title;

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
            workPageContextPillEl.classList.toggle("busy", isBusyForAction);
            // Зелёная капсула = на странице клиентов включены фильтры.
            workPageContextPillEl.classList.toggle(
                "filtered",
                Boolean(filterContexts[pageId]) && hasActiveClientFilters(filterContexts[pageId].filters)
            );
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
                    renderRecipientList();
                } else if (action === "sync-work-inbounds") {
                    await postJson(adminSyncInboundsUrl);
                    const inboundsResp = await fetchJson(adminInboundsUrl, false);
                    workState.inbounds = Array.isArray(inboundsResp?.inbounds) ? inboundsResp.inbounds : [];
                    renderWorkInboundsManager();
                    renderWorkInboundSelectOptions();
                } else if (action === "refresh-work-applications") {
                    await loadApplications();
                } else if (action === "refresh-work-finance") {
                    await loadFinanceSummary();
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

        /** Корневые страницы раздела «Работа»: с них «назад» вести некуда. В режиме
         * админа это вкладки «Пользователи» и «Сервера» (они же нижнее меню). */
        function isWorkRootPage(pageId) {
            if (pageId === "work-menu-page") return true;
            return adminOnlyMode && ["work-clients-page", "work-panels-page", "work-admin-page"].includes(pageId);
        }

        function handleTelegramBack() {
            if (isWorkSheetOpen()) {
                closeWorkSheets();
                return;
            }
            if (isUiSheetOpen()) {
                closeUiSheet(null);
                return;
            }
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
                if (isWorkRootPage(activePageId)) return;
                const backTarget = workBackTargetByPage.get(activePageId);
                if (backTarget) {
                    switchWorkPage(backTarget);
                }
            }
        }

        function shouldShowTelegramBackButton() {
            if (isWorkSheetOpen()) return true;
            const activeScreenId = getActiveScreenId();

            if (activeScreenId === "screen-connections") {
                return true;
            }

            if (activeScreenId === "screen-work") {
                const activePageId = getActiveWorkPageId();
                if (isWorkRootPage(activePageId)) return false;
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

        const SUBSCRIPTION_STATUS_LABELS = {
            active: "Активна",
            lifetime: "Бессрочная",
            paused: "На паузе",
            expired: "Истекла",
            canceled: "Отменена",
            inactive: "Неактивна",
            draft: "Черновик",
        };

        function subscriptionStatusLabel(subscription) {
            if (!subscription) return "Не оформлена";
            if (subscription.is_frozen) return "Заморожена";
            const raw = normalizeSubscriptionStatus(subscription.status);
            return SUBSCRIPTION_STATUS_LABELS[raw] || raw || "—";
        }

        /** Участник группы без собственной цены и дня оплаты: платит администратор группы. */
        function isWorkClientGroupMember(overview) {
            const group = overview?.group;
            if (!group || group.is_admin) return false;
            const sub = overview?.subscription;
            const hasOwnPrice = Number(sub?.price_amount) > 0;
            const hasOwnBillingDay = Number(sub?.billing_day) > 0;
            return !hasOwnPrice && !hasOwnBillingDay;
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
            const hasWorkAccess = ["owner", "admin"].includes(userRole);
            adminOnlyMode = hasWorkAccess;
            profileRoleEl.textContent = userRole;
            workRolePillEl.textContent = userRole;
            workOwnerNameEl.textContent = me?.user?.name || me?.user?.first_name || me?.user?.username || "Панель управления";
            workOwnerRoleEl.textContent = userRole;
            navWorkBtn.classList.toggle("hidden", !hasWorkAccess);
            const canVerify = ["owner", "admin", "support", "moderator"].includes(userRole);
            workVerifyMenuBtnEl?.classList.toggle("hidden", !canVerify);
            bottomNavEl.classList.toggle("with-work", hasWorkAccess);
            if (!hasWorkAccess) {
                document.body.classList.remove("admin-only-mode");
                userBottomNavEl?.classList.remove("hidden");
                adminBottomNavEl?.classList.add("hidden");
                const activeWork = navWorkBtn.classList.contains("active");
                if (activeWork) switchScreen("screen-home");
            } else {
                document.body.classList.add("admin-only-mode");
                userBottomNavEl?.classList.add("hidden");
                adminBottomNavEl?.classList.remove("hidden");
                screens.forEach((screen) => screen.classList.toggle("hidden", screen.id !== "screen-work"));
                heroCardEl?.classList.add("hidden");
                switchScreen("screen-work");
                switchWorkPage("work-clients-page");
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

            const showBuilder = isVerifiedUser;
            subscriptionBuilderEl?.classList.toggle("hidden", !showBuilder);
            if (showBuilder) {
                ensureSubscriptionBuilderLoaded();
            }
        }

        function normalizeItemType(value) {
            return String(value || "").trim().toLowerCase();
        }

        function getPlanMetaItems(plan) {
            const meta = plan?.meta || {};
            const rawItems = [];
            ["items", "addons", "options"].forEach((key) => {
                if (Array.isArray(meta[key])) {
                    rawItems.push(...meta[key]);
                }
            });
            return rawItems.filter((item) => item && typeof item === "object");
        }

        function resolveItemDefinition(catalog, { typeHints = [], codeHints = [], fallbackType = null, fallbackCode = null }) {
            const normalizedTypeHints = typeHints.map((value) => normalizeItemType(value));
            const normalizedCodeHints = codeHints.map((value) => String(value || "").trim().toLowerCase());
            const candidates = catalog.filter((item) => {
                const itemType = normalizeItemType(item.item_type || item.type);
                const code = String(item.code || "").trim().toLowerCase();
                if (!code) return false;
                if (normalizedTypeHints.length && !normalizedTypeHints.includes(itemType)) return false;
                if (normalizedCodeHints.length && !normalizedCodeHints.includes(code)) return false;
                return true;
            });
            const byType = catalog.filter((item) => {
                const itemType = normalizeItemType(item.item_type || item.type);
                return normalizedTypeHints.length && normalizedTypeHints.includes(itemType);
            });
            const byCode = catalog.filter((item) => {
                const code = String(item.code || "").trim().toLowerCase();
                return normalizedCodeHints.length && normalizedCodeHints.includes(code);
            });
            const pick = candidates[0] || byType[0] || byCode[0] || null;
            if (!pick) {
                return {
                    itemType: fallbackType,
                    code: fallbackCode,
                };
            }
            return {
                itemType: normalizeItemType(pick.item_type || pick.type) || fallbackType,
                code: String(pick.code || "").trim() || fallbackCode,
            };
        }

        function setSubscriptionBuilderStatus(message, tone = "") {
            if (!subscriptionBuilderStatusEl) return;
            if (!message) {
                subscriptionBuilderStatusEl.textContent = "";
                subscriptionBuilderStatusEl.classList.add("hidden");
                subscriptionBuilderStatusEl.classList.remove("success", "error");
                return;
            }
            subscriptionBuilderStatusEl.textContent = message;
            subscriptionBuilderStatusEl.classList.remove("hidden");
            subscriptionBuilderStatusEl.classList.toggle("success", tone === "success");
            subscriptionBuilderStatusEl.classList.toggle("error", tone === "error");
        }

        function updateSubscriptionBuilderPrice(pricing) {
            if (!subscriptionPriceValueEl) return;
            subscriptionPriceValueEl.textContent = pricing?.total ? fmtMoney(pricing.total) : "—";
        }

        function renderSubscriptionRegionOptions() {
            if (!subscriptionRegionListEl) return;
            subscriptionRegionListEl.innerHTML = "";
            const regions = subscriptionBuilderState.regions || [];
            if (!regions.length) {
                subscriptionRegionListEl.innerHTML = '<div class="work-note">Регионы не найдены</div>';
                return;
            }
            regions.forEach((region) => {
                const button = document.createElement("button");
                button.type = "button";
                button.className = "subscription-option-btn";
                button.textContent = region.name || region.code || "—";
                const code = String(region.code || "").trim();
                const selected = subscriptionBuilderState.selectedRegions.has(code);
                button.classList.toggle("active", selected);
                button.addEventListener("click", () => {
                    if (!code) return;
                    const alreadySelected = subscriptionBuilderState.selectedRegions.has(code);
                    if (alreadySelected && subscriptionBuilderState.selectedRegions.size === 1) {
                        return;
                    }
                    if (alreadySelected) {
                        subscriptionBuilderState.selectedRegions.delete(code);
                    } else {
                        subscriptionBuilderState.selectedRegions.add(code);
                    }
                    renderSubscriptionRegionOptions();
                    scheduleSubscriptionDraft();
                });
                subscriptionRegionListEl.appendChild(button);
            });
        }

        function renderSubscriptionTrafficOptions() {
            if (!subscriptionTrafficListEl) return;
            subscriptionTrafficListEl.innerHTML = "";
            subscriptionBuilderState.trafficOptions.forEach((option) => {
                const button = document.createElement("button");
                button.type = "button";
                button.className = "subscription-option-btn";
                button.textContent = option.label;
                const selected = subscriptionBuilderState.trafficType === option.key;
                button.classList.toggle("active", selected);
                button.addEventListener("click", () => {
                    subscriptionBuilderState.trafficType = option.key;
                    renderSubscriptionTrafficOptions();
                    scheduleSubscriptionDraft();
                });
                subscriptionTrafficListEl.appendChild(button);
            });
        }

        function buildSubscriptionDraftPayload() {
            const plan = subscriptionBuilderState.plan;
            if (!plan) return null;
            const regions = subscriptionBuilderState.regions || [];
            const selectedRegionCodes = Array.from(subscriptionBuilderState.selectedRegions);
            const regionItems = [];
            const catalog = subscriptionBuilderState.itemsCatalog || [];
            const regionDef = resolveItemDefinition(catalog, {
                typeHints: ["region", "regions"],
                fallbackType: "region",
            });
            selectedRegionCodes.forEach((code) => {
                const region = regions.find((item) => String(item.code) === code);
                if (!code) return;
                regionItems.push({
                    item_type: regionDef.itemType || "region",
                    code,
                    quantity: 1,
                    meta: region?.name ? { name: region.name } : {},
                });
            });

            const trafficKey = subscriptionBuilderState.trafficType || "vless";
            const trafficAliases = {
                vless: ["vless"],
                proxy: ["proxy", "http", "https", "http_proxy", "http-proxy"],
                mixed: ["mixed", "socks", "socks5"],
            };
            const trafficDef = resolveItemDefinition(catalog, {
                typeHints: ["traffic", "protocol", "type"],
                codeHints: trafficAliases[trafficKey] || [trafficKey],
                fallbackType: "traffic",
                fallbackCode: trafficKey,
            });
            const items = [...regionItems];
            items.push({
                item_type: trafficDef.itemType || "traffic",
                code: trafficDef.code || trafficKey,
                quantity: 1,
            });

            const cloudGb = Math.max(0, Number(subscriptionBuilderState.cloudGb) || 0);
            const cloudUnits = Math.floor(cloudGb / 100);
            if (cloudUnits > 0) {
                const cloudDef = resolveItemDefinition(catalog, {
                    typeHints: ["cloud", "storage", "drive"],
                    codeHints: ["cloud", "cloud_100gb", "cloud_100", "storage", "drive"],
                    fallbackType: "cloud",
                    fallbackCode: "cloud_100gb",
                });
                items.push({
                    item_type: cloudDef.itemType || "cloud",
                    code: cloudDef.code || "cloud_100gb",
                    quantity: cloudUnits,
                    meta: { gb: cloudGb },
                });
            }

            return {
                plan_id: plan.id,
                items,
                region_code: selectedRegionCodes[0] || null,
                payload: {
                    region_codes: selectedRegionCodes,
                    traffic_type: trafficKey,
                    cloud_gb: cloudGb,
                },
            };
        }

        async function loadSubscriptionOptions() {
            if (subscriptionBuilderState.optionsLoading) return;
            subscriptionBuilderState.optionsLoading = true;
            setSubscriptionBuilderStatus("Загружаем опции...", "");
            try {
                const result = await fetchJson(subscriptionOptionsUrl, false);
                subscriptionBuilderState.options = result;
                const plans = Array.isArray(result?.plans) ? result.plans : [];
                subscriptionBuilderState.plan = plans.find((plan) => plan?.is_active) || plans[0] || null;
                subscriptionBuilderState.itemsCatalog = getPlanMetaItems(subscriptionBuilderState.plan);
                subscriptionBuilderState.regions = Array.isArray(result?.regions) ? result.regions : [];
                if (!subscriptionBuilderState.selectedRegions.size && subscriptionBuilderState.regions.length) {
                    subscriptionBuilderState.selectedRegions.add(String(subscriptionBuilderState.regions[0].code || ""));
                }
                if (subscriptionBuilderSubEl) {
                    subscriptionBuilderSubEl.textContent = subscriptionBuilderState.plan
                        ? `План: ${subscriptionBuilderState.plan.name}`
                        : "План не найден";
                }
                if (subscriptionCloudGbEl) {
                    subscriptionCloudGbEl.value = subscriptionBuilderState.cloudGb || 0;
                }
                if (subscriptionConfirmBtnEl) {
                    subscriptionConfirmBtnEl.disabled = true;
                }
                renderSubscriptionRegionOptions();
                renderSubscriptionTrafficOptions();
                setSubscriptionBuilderStatus("", "");
                scheduleSubscriptionDraft();
            } catch (err) {
                console.error("subscription options error:", err);
                setSubscriptionBuilderStatus(err?.message || "Не удалось загрузить опции", "error");
            } finally {
                subscriptionBuilderState.optionsLoading = false;
            }
        }

        function ensureSubscriptionBuilderLoaded() {
            if (!subscriptionBuilderEl || !isVerifiedUser) return;
            if (!subscriptionBuilderState.options) {
                loadSubscriptionOptions();
            }
        }

        function scheduleSubscriptionDraft() {
            if (subscriptionBuilderState.draftTimer) {
                clearTimeout(subscriptionBuilderState.draftTimer);
            }
            subscriptionBuilderState.draftTimer = setTimeout(() => {
                refreshSubscriptionDraft();
            }, 450);
        }

        async function refreshSubscriptionDraft() {
            if (subscriptionBuilderState.loading) return;
            if (!subscriptionBuilderState.plan) return;
            if (!subscriptionBuilderState.selectedRegions.size) {
                setSubscriptionBuilderStatus("Выберите хотя бы один регион", "error");
                updateSubscriptionBuilderPrice(null);
                return;
            }
            const payload = buildSubscriptionDraftPayload();
            if (!payload) return;
            const payloadHash = JSON.stringify(payload);
            if (payloadHash === subscriptionBuilderState.lastPayloadHash && subscriptionBuilderState.draft) {
                return;
            }
            subscriptionBuilderState.lastPayloadHash = payloadHash;
            subscriptionBuilderState.loading = true;
            if (subscriptionDraftBtnEl) {
                subscriptionDraftBtnEl.disabled = true;
                subscriptionDraftBtnEl.textContent = "Считаем...";
            }
            if (subscriptionConfirmBtnEl) {
                subscriptionConfirmBtnEl.disabled = true;
            }
            try {
                const result = await postJson(subscriptionDraftUrl, payload);
                subscriptionBuilderState.draft = result?.draft || null;
                subscriptionBuilderState.draftId = result?.draft?.id || null;
                updateSubscriptionBuilderPrice(result?.pricing || null);
                setSubscriptionBuilderStatus("Расчет обновлен", "success");
            } catch (err) {
                console.error("subscription draft error:", err);
                subscriptionBuilderState.draft = null;
                subscriptionBuilderState.draftId = null;
                setSubscriptionBuilderStatus(err?.message || "Не удалось рассчитать", "error");
                updateSubscriptionBuilderPrice(null);
            } finally {
                subscriptionBuilderState.loading = false;
                if (subscriptionDraftBtnEl) {
                    subscriptionDraftBtnEl.disabled = false;
                    subscriptionDraftBtnEl.textContent = "Рассчитать";
                }
                if (subscriptionConfirmBtnEl) {
                    subscriptionConfirmBtnEl.disabled = !subscriptionBuilderState.draftId;
                }
            }
        }

        async function confirmSubscriptionDraft() {
            const draftId = subscriptionBuilderState.draftId;
            if (!draftId) {
                setSubscriptionBuilderStatus("Сначала рассчитайте стоимость", "error");
                return;
            }
            if (subscriptionConfirmBtnEl) {
                subscriptionConfirmBtnEl.disabled = true;
            }
            setSubscriptionBuilderStatus("Подтверждаем...", "");
            try {
                await postJson(subscriptionConfirmUrl, { draft_id: draftId });
                setSubscriptionBuilderStatus("Подписка создана", "success");
                const runtime = await loadRuntimeData();
                renderDashboard(runtime);
            } catch (err) {
                console.error("subscription confirm error:", err);
                setSubscriptionBuilderStatus(err?.message || "Не удалось подтвердить", "error");
            } finally {
                if (subscriptionConfirmBtnEl) {
                    subscriptionConfirmBtnEl.disabled = false;
                }
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

        /** «18.11.2027» - только дата, как её задал администратор (без времени и без сдвига по часовому поясу). */
        function fmtDateOnly(iso) {
            const match = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(iso || ""));
            if (match) return `${match[3]}.${match[2]}.${match[1]}`;
            const d = new Date(iso);
            if (!iso || Number.isNaN(d.getTime())) return "—";
            return d.toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric" });
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
            return `${clean}T23:55:00`; // действует весь выбранный день
        }

        function renderWorkSubscriptionControls(sub) {
            const overview = workState.overview;
            const memberMode = isWorkClientGroupMember(overview);
            document.querySelectorAll("#work-client-actions-overlay [data-hide-for-member]").forEach((el) => {
                el.classList.toggle("hidden", memberMode);
            });
            workClientRemoveMemberBtnEl?.classList.toggle("hidden", !memberMode);
            // Участнику группы блок статуса подписки не нужен совсем.
            workClientStatusChipsEl?.closest(".form-card")?.classList.toggle("hidden", memberMode);
            applyWorkClientLayout(memberMode);

            const currentStatus = normalizeSubscriptionStatus(sub?.status);
            workClientStatusChipsEl?.querySelectorAll("[data-sub-status]").forEach((btn) => {
                const isFrozenChip = btn.dataset.subStatus === "frozen";
                btn.classList.toggle(
                    "active",
                    isFrozenChip ? Boolean(sub?.is_frozen) : (!sub?.is_frozen && btn.dataset.subStatus === currentStatus)
                );
                // Участнику группы доступна только заморозка.
                btn.classList.toggle("hidden", memberMode && !isFrozenChip);
            });
            if (workSubCurrentGroupEl) {
                const ownGroup = overview?.group;
                workSubCurrentGroupEl.classList.toggle("hidden", !ownGroup);
                workSubCurrentGroupEl.textContent = ownGroup
                    ? `Сейчас в группе: ${workGroupLabel(ownGroup, ownGroup.admin_name || "")}`
                    : "";
            }
            workSubTypeChipsEl?.querySelectorAll("[data-sub-type]").forEach((btn) => {
                btn.classList.toggle("active", btn.dataset.subType === (workSubscriptionTypeSelectEl?.value || "personal"));
            });

            const lifetime = isSubscriptionLifetime(sub);
            workClientExtendLifetimeNoteEl?.classList.toggle("hidden", !lifetime);
            workClientManualExtendBtnEl?.classList.toggle("hidden", lifetime);
            workSubExtendWrapEl?.classList.toggle("hidden", lifetime);
            if (workSubCreateDateEl) {
                const untilDate = /^\d{4}-\d{2}-\d{2}/.exec(String(sub?.access_until || ""))?.[0] || "";
                workSubCreateDateEl.value = untilDate && !lifetime ? untilDate : defaultSubscriptionDateValue(30);
            }

            if (workClientMemberNoteEl) {
                const group = overview?.group;
                workClientMemberNoteEl.classList.toggle("hidden", !memberMode);
                workClientMemberNoteEl.textContent = memberMode
                    ? (group?.admin_name
                        ? `Участник группы пользователя «${group.admin_name}»`
                        : `Участник группы «${group?.name || group?.id || ""}»`)
                    : "";
            }
            renderWorkClientGroup(overview);
        }

        function setWorkGroupStatus(message, tone = "") {
            if (!workClientGroupStatusEl) return;
            workClientGroupStatusEl.classList.remove("success", "error");
            if (!message) {
                workClientGroupStatusEl.textContent = "";
                workClientGroupStatusEl.classList.add("hidden");
                return;
            }
            if (tone === "success" || tone === "error") workClientGroupStatusEl.classList.add(tone);
            workClientGroupStatusEl.textContent = message;
            workClientGroupStatusEl.classList.remove("hidden");
        }

        /** Участник добавляется той же формой, что и при создании пользователя. */
        function openGroupMemberForm(group) {
            setWorkGroupStatus("");
            memberPageGroup = group;
            const backBtn = document.querySelector("#work-user-member-page .work-back-btn");
            if (backBtn) backBtn.dataset.workBack = "work-client-group-page";
            workBackTargetByPage.set("work-user-member-page", "work-client-group-page");
            switchWorkPage("work-user-member-page");
        }

        /** Обычный клиент: [Действия][Продлить] / [Подписки][Группа].
         * Участник группы: [Действия][Подписки] / [К Администратору] (продлевает администратор). */
        function applyWorkClientLayout(memberMode) {
            if (!workClientActionsRowEl || !workClientNavRowEl) return;
            if (memberMode) {
                workClientActionsRowEl.replaceChildren(workClientActionsBtnEl, workClientSubscriptionsBtnEl);
                workClientNavRowEl.replaceChildren(workClientToAdminBtnEl);
                workClientExtendBtnEl?.classList.add("hidden");
                workClientGroupBtnEl?.classList.add("hidden");
                workClientToAdminBtnEl?.classList.remove("hidden");
            } else {
                workClientActionsRowEl.replaceChildren(workClientActionsBtnEl, workClientExtendBtnEl);
                workClientNavRowEl.replaceChildren(workClientSubscriptionsBtnEl, workClientGroupBtnEl);
                workClientExtendBtnEl?.classList.remove("hidden");
                workClientToAdminBtnEl?.classList.add("hidden");
            }
        }

        workClientToAdminBtnEl?.addEventListener("click", () => {
            const adminId = workState.overview?.group?.admin_user_id;
            if (!adminId) return;
            openWorkClientPage(adminId).catch((err) => {
                console.error("open group admin error:", err);
                setWorkClientActionStatus(err?.message || "Не удалось открыть профиль администратора", "error");
            });
        });

        function renderWorkClientGroup(overview) {
            const groups = Array.isArray(overview?.administered_groups) ? overview.administered_groups : [];
            workClientGroupBtnEl?.classList.toggle("hidden", !groups.length);
            if (!workClientGroupListEl) return;
            workClientGroupListEl.innerHTML = "";
            if (!groups.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Этот пользователь не администратор группы.";
                workClientGroupListEl.appendChild(empty);
                return;
            }
            groups.forEach((group) => {
                const head = document.createElement("div");
                head.className = "form-card-head";
                const headTitle = document.createElement("div");
                headTitle.className = "work-page-title";
                headTitle.textContent = workGroupLabel(group, workState.overview?.user?.name || "");
                const addBtn = document.createElement("button");
                addBtn.type = "button";
                addBtn.className = "icon-add-btn";
                addBtn.textContent = "+";
                addBtn.setAttribute("aria-label", "Добавить участника");
                addBtn.addEventListener("click", () => openGroupMemberForm(group));
                head.appendChild(headTitle);
                head.appendChild(addBtn);
                workClientGroupListEl.appendChild(head);
                const members = Array.isArray(group?.members) ? group.members : [];
                if (!members.length) {
                    const empty = document.createElement("div");
                    empty.className = "work-empty";
                    empty.textContent = "В группе пока нет участников.";
                    workClientGroupListEl.appendChild(empty);
                    return;
                }
                members.forEach((member) => {
                    const item = document.createElement("div");
                    item.className = "work-link-item work-link-item-clickable";
                    const title = document.createElement("div");
                    title.className = "work-link-item-title";
                    title.textContent = member?.name || member?.username || `Клиент #${member?.id}`;
                    const sub = document.createElement("div");
                    sub.className = "work-link-item-sub";
                    const statusRaw = normalizeSubscriptionStatus(member?.subscription_status);
                    sub.textContent = [
                        member?.username ? `@${member.username}` : "",
                        SUBSCRIPTION_STATUS_LABELS[statusRaw] || "нет подписки",
                    ].filter(Boolean).join(" · ");
                    item.appendChild(title);
                    item.appendChild(sub);
                    item.addEventListener("click", () => {
                        if (!workState.users.some((u) => String(u.id) === String(member.id))) return;
                        openWorkClientPage(member.id).catch((err) => console.error("open group member error:", err));
                    });
                    workClientGroupListEl.appendChild(item);
                });
            });
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
                group_id: user.group_id ?? null,
                subscription_type: user.subscription_type || "personal",
                subscription_status: overview?.subscription?.status ?? null,
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

        
        function renderPendingSubscriptionOverview(overview) {
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
                empty.textContent = "Пока нет пользователей с подпиской. Нажми «Создать пользователя».";
                workClientCardsEl.appendChild(empty);
                return;
            }

            const query = String(workClientSearchEl?.value || "").trim().toLowerCase();
            const searched = query
                ? workState.users.filter((user) => {
                    const name = String(user?.name || "").toLowerCase();
                    const username = String(user?.username || "").toLowerCase();
                    const telegramId = String(user?.telegram_id || "").toLowerCase();
                    const id = String(user?.id || "").toLowerCase();
                    return [name, username, telegramId, id].some((value) => value.includes(query));
                })
                : workState.users;
            const filtered = searched.filter((user) => clientMatchesFilters(user));
            updateClientFilterSummary(filtered.length, workState.users.length);

            if (!filtered.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = hasActiveClientFilters() ? "Нет клиентов под выбранные фильтры." : "Ничего не найдено.";
                workClientCardsEl.appendChild(empty);
                return;
            }

            // Только групповые: показываем семьями - администратор, а под ним его участники.
            if (clientFilters.types.size === 1 && clientFilters.types.has("group")) {
                renderGroupedClientCards(filtered);
                return;
            }
            filtered.forEach((user) => workClientCardsEl.appendChild(buildClientCard(user)));
        }

        function buildClientCard(user, { member = false } = {}) {
            const card = document.createElement("button");
            card.type = "button";
            card.className = member ? "work-client-card work-client-card-member" : "work-client-card";
            card.dataset.userId = String(user.id);

            const head = document.createElement("div");
            head.className = "work-client-card-head";

            const title = document.createElement("div");
            title.className = "work-client-card-title";
            title.textContent = user.name || user.username || `Клиент #${user.id}`;
            head.appendChild(title);

            const chips = document.createElement("div");
            chips.className = "work-client-card-chips";
            const typeLabel = SUBSCRIPTION_TYPE_LABELS[user.subscription_type];
            if (typeLabel) {
                const chip = document.createElement("span");
                chip.className = "work-chip";
                chip.textContent = typeLabel;
                chips.appendChild(chip);
            }
            const status = String(user.subscription_status || "").toLowerCase();
            if (status && !["active", "lifetime"].includes(status)) {
                const chip = document.createElement("span");
                chip.className = "work-chip work-chip-warn";
                chip.textContent = status;
                chips.appendChild(chip);
            }
            if (chips.children.length) head.appendChild(chips);

            const sub = document.createElement("div");
            sub.className = "work-client-card-sub";
            const username = String(user.username || "").replace(/^@/, "");
            sub.textContent = `${username ? `@${username}` : "без username"} · ID ${user.telegram_id || "—"}`;

            card.appendChild(head);
            card.appendChild(sub);
            card.addEventListener("click", () => {
                openWorkClientPage(user.id).catch((err) => {
                    console.error("open client error:", err);
                });
            });
            return card;
        }

        /** Семьи подряд: заголовок, администратор, затем его участники. */
        function renderGroupedClientCards(users) {
            const byGroup = new Map();
            users.forEach((user) => {
                const key = user.group_id || 0;
                if (!byGroup.has(key)) byGroup.set(key, []);
                byGroup.get(key).push(user);
            });
            const entries = [...byGroup.entries()].map(([groupId, items]) => {
                const admin = items.find((u) => u.is_group_admin)
                    || (workState.users || []).find((u) => u.group_id === groupId && u.is_group_admin)
                    || null;
                return { groupId, items, admin };
            });
            const adminLabel = (entry) => String(entry.admin?.name || entry.admin?.username || "").toLowerCase();
            entries.sort((a, b) => adminLabel(a).localeCompare(adminLabel(b)) || a.groupId - b.groupId);
            entries.forEach(({ groupId, items, admin }) => {
                const header = document.createElement("div");
                header.className = "work-client-group-header";
                const adminName = admin?.name || admin?.username || "";
                header.textContent = groupId ? `Семья ${adminName}`.trim() : "Без группы";
                workClientCardsEl.appendChild(header);
                const ordered = [
                    ...items.filter((u) => u.is_group_admin),
                    ...items.filter((u) => !u.is_group_admin).sort((a, b) => a.id - b.id),
                ];
                ordered.forEach((user) => {
                    workClientCardsEl.appendChild(buildClientCard(user, { member: !user.is_group_admin }));
                });
            });
        }

        // ---------- Фильтры клиентов ----------
        const CLIENT_PAYMENT_SOON_DAYS = 14;

        function hasActiveClientFilters(filters = clientFilters) {
            const f = filters;
            return Boolean(
                f.types.size || f.days.size || f.payment.size || f.status.size || f.servers.size
                || f.priceMin !== "" || f.priceMax !== ""
            );
        }

        function parseDateOnlyLocal(iso) {
            const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(iso || ""));
            return m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : null;
        }

        function clientIsGroupMember(user) {
            return Boolean(user?.group_id) && !user?.is_group_admin;
        }

        /** Цена, день оплаты и срок клиента. Участник группы без своих данных платит через администратора. */
        function clientBilling(user) {
            let source = user;
            const hasOwn = Number(user?.price_amount) > 0 || Number(user?.billing_day) > 0;
            if (clientIsGroupMember(user) && !hasOwn) {
                const admin = (workState.users || []).find((u) => u.group_id === user.group_id && u.is_group_admin);
                if (admin) source = admin;
            }
            const rawPrice = source?.price_amount;
            return {
                price: rawPrice === null || rawPrice === undefined || rawPrice === "" ? null : Number(rawPrice),
                day: Number(source?.billing_day) || null,
                until: parseDateOnlyLocal(source?.access_until),
                lifetime: String(source?.subscription_status || "").toLowerCase() === "lifetime",
            };
        }

        /** paid - оплачено надолго; pending - оплата в ближайшие две недели (или сегодня); overdue - просрочено. */
        function clientPaymentState(billing) {
            if (billing.lifetime) return "paid";
            if (!billing.until) return null;
            const now = new Date();
            const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            const days = Math.round((billing.until - today) / 86400000);
            if (days < 0) return "overdue";
            return days <= CLIENT_PAYMENT_SOON_DAYS ? "pending" : "paid";
        }

        function clientStatusKey(user) {
            return user?.is_frozen ? "frozen" : String(user?.subscription_status || "").toLowerCase();
        }

        function clientMatchesFilters(user, filters = clientFilters) {
            const f = filters;
            if (f.types.size) {
                const isGroup = Boolean(user.group_id) || (user.subscription_type && user.subscription_type !== "personal");
                if (!f.types.has(isGroup ? "group" : "personal")) return false;
            }
            const billing = clientBilling(user);
            if (f.priceMin !== "" || f.priceMax !== "") {
                if (billing.price === null || Number.isNaN(billing.price)) return false;
                if (f.priceMin !== "" && billing.price < Number(f.priceMin)) return false;
                if (f.priceMax !== "" && billing.price > Number(f.priceMax)) return false;
            }
            if (f.days.size) {
                const key = billing.day === 15 ? "15" : billing.day === 30 ? "30" : (billing.day ? "other" : null);
                if (!key || !f.days.has(key)) return false;
            }
            if (f.payment.size) {
                const state = clientPaymentState(billing);
                if (!state || !f.payment.has(state)) return false;
            }
            if (f.status.size && !f.status.has(clientStatusKey(user))) return false;
            if (f.servers.size && !(user.servers || []).some((server) => f.servers.has(server.code))) return false;
            return true;
        }

        function updateClientFilterSummary(
            shown, total, filters = clientFilters,
            summaryEl = workClientFilterSummaryEl, textEl = workClientFilterSummaryTextEl,
        ) {
            if (!summaryEl) return;
            const active = hasActiveClientFilters(filters);
            summaryEl.classList.toggle("hidden", !active);
            if (active && textEl) {
                textEl.textContent = `Фильтры включены · найдено ${shown} из ${total}`;
            }
        }

        function renderClientFilterChips() {
            if (workFilterServersEl) {
                const codes = [...new Set((workState.users || []).flatMap((u) => (u.servers || []).map((s) => s.code)).filter(Boolean))].sort();
                workFilterServersEl.innerHTML = "";
                if (!codes.length) {
                    const hint = document.createElement("div");
                    hint.className = "field-hint";
                    hint.textContent = "Серверы появятся, когда у клиентов будут подписки на них.";
                    workFilterServersEl.appendChild(hint);
                }
                codes.forEach((code) => {
                    const chip = document.createElement("button");
                    chip.type = "button";
                    chip.className = "work-chip";
                    chip.dataset.filterValue = code;
                    chip.textContent = code;
                    workFilterServersEl.appendChild(chip);
                });
            }
            workClientsFiltersOverlayEl?.querySelectorAll("[data-filter-group]").forEach((group) => {
                const selected = activeFilters()[group.dataset.filterGroup];
                group.querySelectorAll("[data-filter-value]").forEach((chip) => {
                    chip.classList.toggle("active", Boolean(selected?.has(chip.dataset.filterValue)));
                });
            });
        }

        // Поля цены обновляем только при открытии и сбросе, чтобы не перебивать ввод пользователя.
        function syncClientFilterPriceInputs() {
            const f = activeFilters();
            if (workFilterPriceMinEl) workFilterPriceMinEl.value = f.priceMin;
            if (workFilterPriceMaxEl) workFilterPriceMaxEl.value = f.priceMax;
        }

        function updateClientFilterCount() {
            if (!workFilterApplyEl) return;
            const filters = activeFilters();
            const count = (workState.users || []).filter((user) => clientMatchesFilters(user, filters)).length;
            workFilterApplyEl.textContent = hasActiveClientFilters(filters) ? `Показать (${count})` : "Показать";
        }

        function onClientFiltersChanged() {
            renderClientFilterChips();
            filterContexts[activeFilterPage].rerender();
            updateClientFilterCount();
            updateWorkPageContext(getActiveWorkPageId());
        }

        function resetClientFilters(pageKey = activeFilterPage) {
            activeFilterPage = pageKey;
            const f = activeFilters();
            ["types", "days", "payment", "status", "servers"].forEach((key) => f[key].clear());
            f.priceMin = "";
            f.priceMax = "";
            syncClientFilterPriceInputs();
            onClientFiltersChanged();
        }

        function openClientFilters(pageId = getActiveWorkPageId()) {
            if (filterContexts[pageId]) activeFilterPage = pageId;
            syncClientFilterPriceInputs();
            renderClientFilterChips();
            updateClientFilterCount();
            setWorkSheetVisible(workClientsFiltersOverlayEl, true);
        }

        workClientsFiltersOverlayEl?.addEventListener("click", (event) => {
            if (event.target === workClientsFiltersOverlayEl) {
                setWorkSheetVisible(workClientsFiltersOverlayEl, false);
                return;
            }
            const chip = event.target.closest("[data-filter-value]");
            const group = chip?.closest("[data-filter-group]");
            const selected = group ? activeFilters()[group.dataset.filterGroup] : null;
            if (!chip || !selected) return;
            const value = chip.dataset.filterValue;
            if (selected.has(value)) selected.delete(value);
            else selected.add(value);
            onClientFiltersChanged();
        });
        workFilterPriceMinEl?.addEventListener("input", () => {
            activeFilters().priceMin = workFilterPriceMinEl.value.trim();
            onClientFiltersChanged();
        });
        workFilterPriceMaxEl?.addEventListener("input", () => {
            activeFilters().priceMax = workFilterPriceMaxEl.value.trim();
            onClientFiltersChanged();
        });
        workFilterResetEl?.addEventListener("click", () => resetClientFilters());
        workClientFilterSummaryResetEl?.addEventListener("click", () => resetClientFilters("work-clients-page"));
        workRecipientFilterSummaryResetEl?.addEventListener("click", () => resetClientFilters("work-broadcast-recipients-page"));
        workFilterApplyEl?.addEventListener("click", () => setWorkSheetVisible(workClientsFiltersOverlayEl, false));
        workClientsFiltersCloseEl?.addEventListener("click", () => setWorkSheetVisible(workClientsFiltersOverlayEl, false));

        // ---------- Заявки на регистрацию ----------
        const APP_STATUS_LABELS = {
            new: "новая", reviewing: "рассматривается", need_more_info: "нужна информация",
            approved: "одобрена", rejected: "отклонена", cancelled: "отменена",
        };

        function appDisplayName(app) {
            return app.full_name || app.tg_name || (app.username ? `@${app.username}` : `#${app.user_id}`);
        }

        function appMeta(app) {
            return [app.username ? `@${app.username}` : "без username", `TG ${app.telegram_id || "—"}`].join(" · ");
        }

        function updateApplicationsHub() {
            const open = appsState.items.filter((a) => OPEN_APP_STATUSES.includes(a.status)).length;
            if (workAdminApplicationsLabelEl) {
                workAdminApplicationsLabelEl.textContent = open ? `Заявки · ${open}` : "Заявки";
            }
        }

        async function loadApplications({ quiet = false } = {}) {
            if (appsState.loading) return;
            appsState.loading = true;
            try {
                const response = await fetchJson(adminApplicationsUrl, false);
                appsState.items = Array.isArray(response?.applications) ? response.applications : [];
                updateApplicationsHub();
                renderApplicationsList();
            } catch (err) {
                console.error("load applications error:", err);
                if (!quiet) setFormNote(workApplicationsStatusEl, err?.message || "Не удалось загрузить заявки", "error");
            } finally {
                appsState.loading = false;
            }
        }

        function renderApplicationsList() {
            if (!workApplicationsListEl) return;
            workApplicationsFilterEl?.querySelectorAll("[data-app-filter]").forEach((chip) => {
                chip.classList.toggle("active", chip.dataset.appFilter === appsState.filter);
            });
            const items = appsState.filter === "open"
                ? appsState.items.filter((a) => OPEN_APP_STATUSES.includes(a.status))
                : appsState.items;
            workApplicationsListEl.innerHTML = "";
            if (!items.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = appsState.filter === "open" ? "Новых заявок нет 🎉" : "Заявок пока нет.";
                workApplicationsListEl.appendChild(empty);
                return;
            }
            items.forEach((app) => {
                const row = document.createElement("button");
                row.type = "button";
                row.className = `app-row${OPEN_APP_STATUSES.includes(app.status) ? " new" : ""}`;
                row.innerHTML = `<span class="avatar" aria-hidden="true">👤</span>
                    <span class="app-row-text"><div class="app-row-name"></div><div class="app-row-sub"></div></span>
                    <span class="app-row-badge"></span>`;
                row.querySelector(".app-row-name").textContent = appDisplayName(app);
                row.querySelector(".app-row-sub").textContent =
                    `${appMeta(app)}${app.created_at ? ` · ${fmtDateOnly(app.created_at)}` : ""}`;
                row.querySelector(".app-row-badge").textContent = APP_STATUS_LABELS[app.status] || app.status;
                row.addEventListener("click", () => {
                    openApplication(app).catch((err) => {
                        console.error("open application error:", err);
                        setFormNote(workApplicationsStatusEl, err?.message || "Не удалось открыть заявку", "error");
                    });
                });
                workApplicationsListEl.appendChild(row);
            });
        }

        workApplicationsFilterEl?.addEventListener("click", (event) => {
            const chip = event.target.closest("[data-app-filter]");
            if (!chip) return;
            appsState.filter = chip.dataset.appFilter;
            renderApplicationsList();
        });
        workAdminApplicationsBtnEl?.addEventListener("click", () => switchWorkPage("work-applications-page"));

        /** Включает/выключает вид «рассмотрение заявки» на форме создания пользователя. */
        function setApplicationMode(app) {
            applicationMode = app || null;
            const on = Boolean(app);
            workAppBlockEl?.classList.toggle("hidden", !on);
            workAppReplyCardEl?.classList.toggle("hidden", !on);
            workAppRejectBtnEl?.classList.toggle("hidden", !on);
            workUserWhoCardEl?.classList.toggle("hidden", on);
            if (workUserCreateTitleEl) workUserCreateTitleEl.textContent = on ? `Заявка №${app.id}` : "Новый пользователь";
            if (workUserCreateSubmitEl) workUserCreateSubmitEl.textContent = on ? "Подтвердить заявку" : "Создать пользователя";
            if (workAppReplyEl) workAppReplyEl.value = "";
            const backBtn = document.querySelector("#work-user-create-page > .work-page-head .work-back-btn");
            const backTarget = on ? "work-applications-page" : "work-clients-page";
            if (backBtn) backBtn.dataset.workBack = backTarget;
            workBackTargetByPage.set("work-user-create-page", backTarget);
            updateWorkPageContext(getActiveWorkPageId());  // в капсуле «Заявка №N» вместо «Новый пользователь»
            if (on) {
                if (workAppNameEl) workAppNameEl.textContent = appDisplayName(app);
                if (workAppMetaEl) workAppMetaEl.textContent = appMeta(app);
                if (workAppMessageEl) workAppMessageEl.textContent = app.extra_info || "Клиент ничего не добавил";
            }
        }

        async function openApplication(app) {
            if (!OPEN_APP_STATUSES.includes(app.status)) {
                await askCenterModal({
                    title: `Заявка №${app.id}`,
                    text: [
                        `ФИО: ${app.full_name}`,
                        `Статус: ${APP_STATUS_LABELS[app.status] || app.status}`,
                        `Сообщение: ${app.extra_info || "—"}`,
                        app.review_note ? `Комментарий: ${app.review_note}` : "",
                    ].filter(Boolean).join("\n"),
                    rows: [[{ id: "close", label: "Закрыть" }]],
                });
                return;
            }
            const fresh = (await fetchJson(`${adminApplicationsUrl}/${app.id}`, false))?.application || app;
            if (!OPEN_APP_STATUSES.includes(fresh.status)) {
                await loadApplications();
                return;
            }
            // Входим на форму создания (она сбрасывается при входе), затем выбираем клиента из заявки.
            switchWorkPage("work-user-create-page");
            setApplicationMode(fresh);
            if (workUserCreateModeEl) workUserCreateModeEl.value = "existing";
            if (workUserExistingSelectEl) {
                let option = [...workUserExistingSelectEl.options].find((o) => o.value === String(fresh.user_id));
                if (!option) {
                    option = document.createElement("option");
                    option.value = String(fresh.user_id);
                    workUserExistingSelectEl.appendChild(option);
                }
                option.textContent = appDisplayName(fresh);
                option.dataset.metaTop = fresh.username ? `@${fresh.username}` : "без username";
                option.dataset.metaBottom = `ID ${fresh.telegram_id || "—"}`;
                workUserExistingSelectEl.value = String(fresh.user_id);
                workUserExistingSelectEl.dispatchEvent(new Event("change", { bubbles: true }));
            }
            updateUserCreateMode();
        }

        workAppRejectBtnEl?.addEventListener("click", async () => {
            const application = applicationMode;
            if (!application) return;
            const choice = await askCenterModal({
                title: "Отклонить заявку?",
                text: "Клиент получит сообщение. Причину можно указать ниже, это необязательно.",
                inputPlaceholder: "Причина отказа",
                rows: [[{ id: "cancel", label: "Отмена" }, { id: "reject", label: "Отклонить", variant: "danger" }]],
            });
            if (choice !== "reject") return;
            const reason = lastCenterModalInput.trim();
            workAppRejectBtnEl.disabled = true;
            try {
                const result = await postJson(`${adminApplicationsUrl}/${application.id}/reject`, { reason });
                setApplicationMode(null);
                switchWorkPage("work-applications-page");
                setFormNote(
                    workApplicationsStatusEl,
                    result?.notified ? "Заявка отклонена, клиент получил сообщение" : "Заявка отклонена, но сообщение клиенту отправить не удалось",
                    result?.notified ? "success" : "error"
                );
            } catch (err) {
                console.error("reject application error:", err);
                setFormNote(workUserCreateStatusEl, err?.message || "Не удалось отклонить заявку", "error");
            } finally {
                workAppRejectBtnEl.disabled = false;
            }
        });

        // ---------- Финансы ----------
        const FINANCE_DAY_LABELS = [
            ["15", "15-е число"], ["30", "30-е число"], ["other", "Другие дни"], ["none", "Без даты оплаты"],
        ];

        function setFinanceStatus(message, tone = "") {
            setFormNote(finEl("fin-status"), message, tone);
        }

        async function loadFinanceSummary() {
            if (financeState.loading) return;
            financeState.loading = true;
            try {
                const response = await fetchJson(adminFinanceSummaryUrl, false);
                financeState.summary = response?.summary || null;
                setFinanceStatus("");
                renderFinance();
            } catch (err) {
                console.error("finance summary error:", err);
                setFinanceStatus(err?.message || "Не удалось загрузить финансы", "error");
            } finally {
                financeState.loading = false;
            }
        }

        function financeNumber(value) {
            const n = Number(value);
            return Number.isFinite(n) ? n : 0;
        }

        function renderFinance() {
            const summary = financeState.summary;
            if (!summary) return;
            const receipts = financeNumber(summary.receipts);
            const expenses = financeNumber(summary.expenses);
            const income = financeNumber(summary.income);
            const debt = financeNumber(summary.debt?.amount);
            const debtCount = Number(summary.debt?.count || 0);
            const next = summary.next_payment;

            finEl("fin-receipts").textContent = fmtMoney(receipts);
            finEl("fin-receipts-sub").textContent = `платят: ${summary.payers || 0}`;
            finEl("fin-next").textContent = next ? fmtMoney(next.amount) : "—";
            finEl("fin-next-sub").textContent = next ? `${fmtDateOnly(next.date)} · ${peopleText(next.payers)}` : "нет платёжных дней";
            finEl("fin-income").textContent = fmtMoney(income);
            const incomeTile = finEl("fin-income-tile");
            incomeTile.classList.toggle("positive", income > 0);
            incomeTile.classList.toggle("negative", income < 0);
            finEl("fin-debt").textContent = fmtMoney(debt);
            finEl("fin-debt-sub").textContent = debtCount ? peopleText(debtCount) : "должников нет";
            finEl("fin-debt-tile").classList.toggle("has-debt", debt > 0);

            finEl("fin-d-receipts").textContent = fmtMoney(receipts);
            finEl("fin-d-expenses").textContent = fmtMoney(expenses);
            finEl("fin-d-income").textContent = fmtMoney(income);
            finEl("fin-d-debt").textContent = fmtMoney(debt);
            finEl("fin-d-debt-count").textContent = String(debtCount);

            const byDay = finEl("fin-by-day");
            byDay.innerHTML = "";
            FINANCE_DAY_LABELS.forEach(([key, label]) => {
                const entry = summary.by_day?.[key];
                if (!entry) return;
                const row = document.createElement("div");
                row.className = "finance-row";
                const left = document.createElement("span");
                left.textContent = label;
                const small = document.createElement("small");
                small.textContent = peopleText(entry.payers);
                left.appendChild(small);
                const value = document.createElement("b");
                value.textContent = fmtMoney(entry.amount);
                row.appendChild(left);
                row.appendChild(value);
                byDay.appendChild(row);
            });
            if (!byDay.children.length) {
                const empty = document.createElement("div");
                empty.className = "field-hint";
                empty.textContent = "Платящих клиентов пока нет.";
                byDay.appendChild(empty);
            }

            const list = finEl("fin-debtors-list");
            list.innerHTML = "";
            const debtors = Array.isArray(summary.debtors) ? summary.debtors : [];
            if (!debtors.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Должников нет 🎉";
                list.appendChild(empty);
            }
            debtors.forEach((debtor) => {
                const card = document.createElement("div");
                card.className = "finance-debtor";
                const name = document.createElement("div");
                name.className = "finance-debtor-name";
                name.textContent = debtor.name || `#${debtor.user_id}`;
                if (debtor.periods > 1) {
                    const small = document.createElement("small");
                    small.textContent = `${debtor.periods} ${pluralRu(debtor.periods, ["период", "периода", "периодов"])}`;
                    name.appendChild(small);
                }
                const tiles = document.createElement("div");
                tiles.className = "finance-debtor-tiles";
                const makeMini = (cls, label, value) => {
                    const mini = document.createElement("div");
                    mini.className = `finance-mini ${cls}`;
                    const l = document.createElement("div");
                    l.className = "finance-mini-label";
                    l.textContent = label;
                    const v = document.createElement("div");
                    v.className = "finance-mini-value";
                    v.textContent = value;
                    mini.appendChild(l);
                    mini.appendChild(v);
                    return mini;
                };
                tiles.appendChild(makeMini("owed", "Должен", fmtMoney(debtor.amount)));
                tiles.appendChild(makeMini("date", "Дата", fmtDateOnly(debtor.due_date)));
                card.appendChild(name);
                card.appendChild(tiles);
                list.appendChild(card);
            });

            const input = finEl("fin-expenses-input");
            if (input && document.activeElement !== input) input.value = expenses ? String(expenses) : "";
        }

        workAdminFinanceBtnEl?.addEventListener("click", () => switchWorkPage("work-finance-page"));
        finEl("fin-details-btn")?.addEventListener("click", () => switchWorkPage("work-finance-details-page"));
        finEl("fin-expenses-btn")?.addEventListener("click", () => switchWorkPage("work-finance-expenses-page"));
        finEl("fin-debtors-btn")?.addEventListener("click", () => switchWorkPage("work-finance-debtors-page"));
        finEl("fin-d-debtors-btn")?.addEventListener("click", () => switchWorkPage("work-finance-debtors-page"));
        finEl("fin-expenses-save")?.addEventListener("click", async () => {
            const statusEl = finEl("fin-expenses-status");
            const raw = String(finEl("fin-expenses-input")?.value || "").trim();
            if (raw === "") return setFormNote(statusEl, "Введите сумму расходов", "error");
            const button = finEl("fin-expenses-save");
            button.disabled = true;
            setFormNote(statusEl, "Сохраняем…");
            try {
                const result = await postJson(adminFinanceExpensesUrl, { amount: raw });
                financeState.summary = result?.summary || financeState.summary;
                renderFinance();
                setFormNote(statusEl, "Сохранено", "success");
            } catch (err) {
                console.error("save expenses error:", err);
                setFormNote(statusEl, err?.message || "Не удалось сохранить", "error");
            } finally {
                button.disabled = false;
            }
        });

        // ---------- Администрирование: рассылка ----------
        const BROADCAST_TYPE_LABELS = { ad: "Реклама", news: "Новости", important: "Важное", maintenance: "Технические работы" };

        function pluralRu(n, forms) {
            const mod100 = Math.abs(n) % 100;
            const mod10 = mod100 % 10;
            if (mod100 > 10 && mod100 < 20) return forms[2];
            if (mod10 === 1) return forms[0];
            if (mod10 >= 2 && mod10 <= 4) return forms[1];
            return forms[2];
        }

        const peopleText = (n) => `${n} ${pluralRu(n, ["человек", "человека", "человек"])}`;

        function isCenterModalOpen() {
            return Boolean(workCenterModalEl && !workCenterModalEl.classList.contains("hidden"));
        }

        let centerModalResolve = null;

        function closeCenterModal(result = "cancel") {
            if (!isCenterModalOpen()) return;
            lastCenterModalInput = String(workCenterModalInputEl?.value || "");
            workCenterModalEl.classList.add("hidden");
            workCenterModalEl.setAttribute("aria-hidden", "true");
            const resolve = centerModalResolve;
            centerModalResolve = null;
            if (resolve) resolve(result);
            updateTelegramBackButton();
        }

        /** Окно по центру экрана. rows - строки кнопок: [{id, label, variant, toggleList}]. Возвращает id нажатой кнопки. */
        function askCenterModal({ title, text = "", listLines = null, rows, inputPlaceholder = null }) {
            if (!workCenterModalEl) return Promise.resolve("cancel");
            closeCenterModal("cancel");
            if (workCenterModalInputEl) {
                workCenterModalInputEl.value = "";
                workCenterModalInputEl.placeholder = inputPlaceholder || "";
                workCenterModalInputEl.classList.toggle("hidden", inputPlaceholder === null);
            }
            workCenterModalTitleEl.textContent = title;
            workCenterModalTextEl.textContent = text;
            workCenterModalListEl.innerHTML = "";
            workCenterModalListEl.classList.add("hidden");
            (listLines || []).forEach((line) => {
                const item = document.createElement("div");
                item.textContent = line;
                workCenterModalListEl.appendChild(item);
            });
            workCenterModalActionsEl.innerHTML = "";
            rows.forEach((row) => {
                const rowEl = document.createElement("div");
                rowEl.className = "work-modal-row";
                row.forEach((btn) => {
                    const el = document.createElement("button");
                    el.type = "button";
                    el.className = `work-modal-btn ${btn.variant || ""}`.trim();
                    el.textContent = btn.label;
                    el.addEventListener("click", () => {
                        if (btn.toggleList) {
                            const hidden = workCenterModalListEl.classList.toggle("hidden");
                            el.textContent = hidden ? btn.label : "Скрыть список";
                            return;
                        }
                        closeCenterModal(btn.id);
                    });
                    rowEl.appendChild(el);
                });
                workCenterModalActionsEl.appendChild(rowEl);
            });
            workCenterModalEl.classList.remove("hidden");
            workCenterModalEl.setAttribute("aria-hidden", "false");
            updateTelegramBackButton();
            return new Promise((resolve) => {
                centerModalResolve = resolve;
            });
        }

        function recipientLabel(user) {
            return user?.name || (user?.username ? `@${user.username}` : `Клиент #${user?.id}`);
        }

        function recipientCanReceive(user) {
            return /^\d+$/.test(String(user?.telegram_id || "").trim());
        }

        function visibleRecipients() {
            const query = String(workRecipientSearchEl?.value || "").trim().toLowerCase();
            return (workState.users || []).filter((user) => {
                if (query) {
                    const haystack = [user?.name, user?.username, user?.telegram_id, user?.id]
                        .map((value) => String(value || "").toLowerCase());
                    if (!haystack.some((value) => value.includes(query))) return false;
                }
                return clientMatchesFilters(user, recipientFilters);
            });
        }

        function updateSelectionBar() {
            const count = broadcastState.selected.size;
            if (workSelectionConfirmEl) {
                workSelectionConfirmEl.disabled = count === 0;
                workSelectionConfirmEl.textContent = count ? `✓ ${count}` : "✓";
            }
        }

        function renderRecipientList() {
            if (!workRecipientListEl) return;
            workRecipientListEl.innerHTML = "";
            const all = workState.users || [];
            const list = visibleRecipients();
            updateClientFilterSummary(
                list.length, all.length, recipientFilters,
                workRecipientFilterSummaryEl, workRecipientFilterSummaryTextEl
            );
            if (!list.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = all.length ? "Никого не найдено." : "Список клиентов пуст.";
                workRecipientListEl.appendChild(empty);
                updateSelectionBar();
                return;
            }
            list.forEach((user) => {
                const canReceive = recipientCanReceive(user);
                const row = document.createElement("button");
                row.type = "button";
                row.className = "work-recipient-row";
                row.dataset.userId = String(user.id);
                row.classList.toggle("selected", broadcastState.selected.has(user.id));
                row.classList.toggle("disabled", !canReceive);
                const username = String(user.username || "").replace(/^@/, "");
                const sub = !canReceive ? "нет Telegram ID" : (username ? `@${username}` : "");
                row.innerHTML = `
                    <span class="work-recipient-check" aria-hidden="true">✓</span>
                    <span class="work-recipient-avatar" aria-hidden="true">👤</span>
                    <span class="work-recipient-text">
                        <div class="work-recipient-name"></div>
                        <div class="work-recipient-sub"></div>
                    </span>`;
                row.querySelector(".work-recipient-name").textContent = recipientLabel(user);
                const subEl = row.querySelector(".work-recipient-sub");
                subEl.textContent = sub;
                if (!sub) subEl.remove();
                row.addEventListener("click", () => {
                    if (!canReceive) return;
                    if (broadcastState.selected.has(user.id)) broadcastState.selected.delete(user.id);
                    else broadcastState.selected.add(user.id);
                    row.classList.toggle("selected", broadcastState.selected.has(user.id));
                    updateSelectionBar();
                });
                workRecipientListEl.appendChild(row);
            });
            updateSelectionBar();
        }

        workRecipientSearchEl?.addEventListener("input", renderRecipientList);
        workSelectionAllEl?.addEventListener("click", () => {
            visibleRecipients().filter(recipientCanReceive).forEach((user) => broadcastState.selected.add(user.id));
            renderRecipientList();
        });
        workSelectionClearEl?.addEventListener("click", () => {
            broadcastState.selected.clear();
            renderRecipientList();
        });
        workSelectionConfirmEl?.addEventListener("click", async () => {
            const ids = [...broadcastState.selected];
            if (!ids.length) return;
            const byId = new Map((workState.users || []).map((user) => [user.id, user]));
            const choice = await askCenterModal({
                title: "Выбор получателей",
                text: `Вы выбрали ${peopleText(ids.length)} для рассылки`,
                listLines: ids.map((id, i) => `${i + 1}. ${recipientLabel(byId.get(id) || { id })}`),
                rows: [
                    [{ id: "list", label: "Список", toggleList: true }],
                    [{ id: "cancel", label: "Отменить" }, { id: "confirm", label: "Подтвердить", variant: "primary" }],
                ],
            });
            if (choice !== "confirm") return;  // отмена - остаёмся на выборе людей
            broadcastState.recipientIds = ids;
            switchWorkPage("work-broadcast-page");
        });

        function setBroadcastStatus(message, tone = "") {
            setFormNote(workBroadcastStatusEl, message, tone);
        }

        function renderBroadcastPage() {
            workBroadcastTypesEl?.querySelectorAll("[data-broadcast-type]").forEach((chip) => {
                chip.classList.toggle("active", chip.dataset.broadcastType === broadcastState.type);
            });
            const count = broadcastState.recipientIds.length;
            if (workBroadcastSummaryEl) {
                workBroadcastSummaryEl.textContent = count ? `Выбрано: ${peopleText(count)}` : "Не выбраны";
            }
            if (workBroadcastPickEl) {
                workBroadcastPickEl.textContent = count ? "Изменить получателей" : "Выбрать получателей";
            }
        }

        workBroadcastTypesEl?.addEventListener("click", (event) => {
            const chip = event.target.closest("[data-broadcast-type]");
            if (!chip) return;
            broadcastState.type = chip.dataset.broadcastType;
            renderBroadcastPage();
        });
        workBroadcastPickEl?.addEventListener("click", () => switchWorkPage("work-broadcast-recipients-page"));
        workAdminNotificationsBtnEl?.addEventListener("click", () => switchWorkPage("work-broadcast-page"));

        workBroadcastSendEl?.addEventListener("click", async () => {
            if (broadcastState.sending) return;
            const type = broadcastState.type;
            const text = String(workBroadcastTextEl?.value || "").trim();
            const ids = broadcastState.recipientIds.slice();
            if (!type) return setBroadcastStatus("Выберите тип сообщения", "error");
            if (!ids.length) return setBroadcastStatus("Выберите получателей", "error");
            if (!text) return setBroadcastStatus("Введите текст рассылки", "error");
            setBroadcastStatus("");
            const choice = await askCenterModal({
                title: "Отправить рассылку?",
                text: `Тип: ${BROADCAST_TYPE_LABELS[type]}\nПолучателей: ${ids.length}`,
                rows: [[{ id: "cancel", label: "Отмена" }, { id: "send", label: "Отправить", variant: "primary" }]],
            });
            if (choice !== "send") return;
            broadcastState.sending = true;
            workBroadcastSendEl.disabled = true;
            setBroadcastStatus("Отправляем…");
            try {
                const result = await postJson(adminBroadcastsUrl, { type, text, user_ids: ids });
                renderBroadcastResult(result);
                if (workBroadcastTextEl) workBroadcastTextEl.value = "";  // чтобы случайно не отправить повторно
                setBroadcastStatus("");
            } catch (err) {
                console.error("broadcast error:", err);
                setBroadcastStatus(err?.message || "Не удалось отправить рассылку", "error");
            } finally {
                broadcastState.sending = false;
                workBroadcastSendEl.disabled = false;
            }
        });

        function renderBroadcastResult(result) {
            if (!workBroadcastResultEl) return;
            const failed = Array.isArray(result?.failed) ? result.failed : [];
            workBroadcastResultEl.classList.remove("hidden");
            if (workBroadcastResultTextEl) {
                workBroadcastResultTextEl.textContent =
                    `Доставлено: ${result?.sent ?? 0} из ${result?.total ?? 0}`
                    + (failed.length ? ` · не доставлено: ${failed.length}` : "")
                    + (result?.log_posted ? "" : " · лог в группу не отправлен");
            }
            if (workBroadcastResultListEl) {
                workBroadcastResultListEl.innerHTML = "";
                failed.forEach((item) => {
                    const row = document.createElement("div");
                    row.className = "work-link-item";
                    const title = document.createElement("div");
                    title.className = "work-link-item-title";
                    title.textContent = item.name || (item.username ? `@${item.username}` : `#${item.user_id}`);
                    const sub = document.createElement("div");
                    sub.className = "work-link-item-sub";
                    sub.textContent = item.reason || "—";
                    row.appendChild(title);
                    row.appendChild(sub);
                    workBroadcastResultListEl.appendChild(row);
                });
            }
        }

        // ---------- UI-кит: bottom sheet и красивые селекты ----------
        const uiSheetState = { resolve: null, items: [], selected: "", emptyText: "" };

        function isUiSheetOpen() {
            return Boolean(uiSheetOverlayEl && !uiSheetOverlayEl.classList.contains("hidden"));
        }

        function closeUiSheet(result = null) {
            if (!isUiSheetOpen()) return;
            uiSheetOverlayEl.classList.add("hidden");
            uiSheetOverlayEl.setAttribute("aria-hidden", "true");
            document.body.classList.remove("ui-sheet-open");
            const resolve = uiSheetState.resolve;
            uiSheetState.resolve = null;
            uiSheetState.items = [];
            if (uiSheetSearchEl) uiSheetSearchEl.value = "";
            if (resolve) resolve(result);
        }

        function renderUiSheetItems() {
            if (!uiSheetListEl) return;
            const query = String(uiSheetSearchEl?.value || "").trim().toLowerCase();
            uiSheetListEl.innerHTML = "";
            const rows = uiSheetState.items.filter((item) => !query || item.search.includes(query));
            if (!rows.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = uiSheetState.emptyText || "Ничего не найдено.";
                uiSheetListEl.appendChild(empty);
                return;
            }
            rows.forEach((item) => {
                const selected = String(item.value) === String(uiSheetState.selected);
                const btn = document.createElement("button");
                btn.type = "button";
                btn.className = "ui-sheet-item";
                btn.classList.toggle("selected", selected);
                btn.setAttribute("role", "option");
                btn.setAttribute("aria-selected", selected ? "true" : "false");

                const main = document.createElement("span");
                main.className = "ui-sheet-item-main";
                main.textContent = item.label;
                btn.appendChild(main);

                const metaLines = (item.meta || []).filter(Boolean).slice(0, 2);
                if (metaLines.length) {
                    const meta = document.createElement("span");
                    meta.className = "ui-sheet-item-meta";
                    metaLines.forEach((line) => {
                        const row = document.createElement("span");
                        row.textContent = line;
                        meta.appendChild(row);
                    });
                    btn.appendChild(meta);
                }
                if (selected) {
                    const check = document.createElement("span");
                    check.className = "ui-sheet-check";
                    check.setAttribute("aria-hidden", "true");
                    check.textContent = "✓";
                    btn.appendChild(check);
                }
                btn.addEventListener("click", () => closeUiSheet(String(item.value)));
                uiSheetListEl.appendChild(btn);
            });
        }

        /** Открывает нижнюю шторку выбора. Резолвится значением выбранного пункта или null. */
        function openUiSheet({ title = "Выбор", items = [], selected = "", searchable = false, emptyText = "" } = {}) {
            if (!uiSheetOverlayEl) return Promise.resolve(null);
            if (isUiSheetOpen()) closeUiSheet(null);
            uiSheetState.items = items.map((item) => ({
                ...item,
                search: [item.label, ...(item.meta || [])].join(" ").toLowerCase(),
            }));
            uiSheetState.selected = selected;
            uiSheetState.emptyText = emptyText;
            if (uiSheetTitleEl) uiSheetTitleEl.textContent = title;
            if (uiSheetSearchEl) {
                uiSheetSearchEl.classList.toggle("hidden", !searchable);
                uiSheetSearchEl.value = "";
            }
            renderUiSheetItems();
            uiSheetOverlayEl.classList.remove("hidden");
            uiSheetOverlayEl.setAttribute("aria-hidden", "false");
            document.body.classList.add("ui-sheet-open");
            if (uiSheetListEl) uiSheetListEl.scrollTop = 0;
            return new Promise((resolve) => {
                uiSheetState.resolve = resolve;
            });
        }

        function syncSheetSelect(select, trigger) {
            const option = select.selectedIndex >= 0 ? select.options[select.selectedIndex] : null;
            const hasValue = Boolean(option && option.value !== "");
            trigger.innerHTML = "";
            const text = document.createElement("span");
            text.className = "ui-select-text";
            text.textContent = option ? option.textContent : (select.dataset.placeholder || "Выбрать");
            trigger.appendChild(text);
            const metaLines = hasValue ? [option.dataset.metaTop, option.dataset.metaBottom].filter(Boolean) : [];
            if (metaLines.length) {
                const meta = document.createElement("span");
                meta.className = "ui-select-meta";
                metaLines.forEach((line) => {
                    const row = document.createElement("span");
                    row.textContent = line;
                    meta.appendChild(row);
                });
                trigger.appendChild(meta);
            }
            const chevron = document.createElement("span");
            chevron.className = "ui-select-chevron";
            chevron.setAttribute("aria-hidden", "true");
            trigger.appendChild(chevron);
            trigger.classList.toggle("is-placeholder", !hasValue);
            trigger.disabled = Boolean(select.disabled);
        }

        function syncSegmentedSelect(select, seg) {
            seg.innerHTML = "";
            Array.from(select.options).forEach((option) => {
                const active = option.value === select.value;
                const btn = document.createElement("button");
                btn.type = "button";
                btn.className = "ui-seg-btn";
                btn.classList.toggle("active", active);
                btn.setAttribute("role", "tab");
                btn.setAttribute("aria-selected", active ? "true" : "false");
                btn.disabled = Boolean(select.disabled);
                btn.textContent = option.textContent;
                btn.addEventListener("click", () => {
                    if (select.value === option.value) return;
                    select.value = option.value;
                    select.dispatchEvent(new Event("change", { bubbles: true }));
                });
                seg.appendChild(btn);
            });
        }

        /**
         * Заменяет нативный <select> красивым контролом (шторка или сегменты).
         * Сам <select> остаётся в DOM скрытым и остаётся источником истины,
         * поэтому весь остальной код продолжает читать/писать select.value.
         */
        function enhanceSelect(select) {
            if (!select || select.dataset.uiEnhanced === "1") return;
            select.dataset.uiEnhanced = "1";
            select.classList.add("ui-native");
            const segmented = select.dataset.ui === "segmented";
            const control = document.createElement(segmented ? "div" : "button");
            if (segmented) {
                control.className = "ui-seg";
                control.setAttribute("role", "tablist");
            } else {
                control.type = "button";
                control.className = "ui-select";
                control.setAttribute("aria-haspopup", "listbox");
            }
            select.insertAdjacentElement("afterend", control);

            const sync = () => (segmented ? syncSegmentedSelect(select, control) : syncSheetSelect(select, control));

            // программная установка select.value не шлёт события - ловим её сами
            const valueDescriptor = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value");
            Object.defineProperty(select, "value", {
                configurable: true,
                get() {
                    return valueDescriptor.get.call(this);
                },
                set(next) {
                    valueDescriptor.set.call(this, next);
                    sync();
                },
            });
            select.addEventListener("change", sync);
            new MutationObserver(sync).observe(select, {
                childList: true,
                subtree: true,
                characterData: true,
                attributes: true,
                attributeFilter: ["disabled", "label"],
            });

            if (!segmented) {
                control.addEventListener("click", async () => {
                    const rows = Array.from(select.options).filter((option) => option.value !== "");
                    const picked = await openUiSheet({
                        title: select.dataset.sheetTitle || select.getAttribute("aria-label") || "Выбор",
                        selected: select.value,
                        searchable: select.dataset.searchable === "true" || rows.length > 8,
                        emptyText: select.dataset.emptyText || "Список пуст.",
                        items: rows.map((option) => ({
                            value: option.value,
                            label: option.textContent,
                            meta: [option.dataset.metaTop, option.dataset.metaBottom],
                        })),
                    });
                    if (picked === null || picked === select.value) return;
                    select.value = picked;
                    select.dispatchEvent(new Event("change", { bubbles: true }));
                });
            }
            sync();
        }

        function enhanceWorkSelects() {
            document.querySelectorAll("#screen-work select, #work-client-actions-overlay select[data-ui]").forEach(enhanceSelect);
        }

        function setFormNote(el, message, tone = "") {
            if (!el) return;
            el.classList.remove("success", "error");
            if (!message) {
                el.textContent = "";
                el.classList.add("hidden");
                return;
            }
            if (tone === "success" || tone === "error") el.classList.add(tone);
            el.textContent = message;
            el.classList.remove("hidden");
        }

        // ---------- Создание пользователя ----------
        const createDraft = { bindings: [], members: [] };
        const memberDraft = { bindings: [] };
        // Не null, когда форма участника открыта со страницы «Группа» существующего администратора.
        let memberPageGroup = null;

        const SUBSCRIPTION_TYPE_LABELS = {
            personal: "Личная",
            family_admin: "Админ семьи",
            family_member: "Участник",
        };

        /** Telegram ID (только цифры) или @username -> { telegram_id, username } либо null. */
        function parseTelegramIdentity(raw) {
            const value = String(raw || "").trim();
            if (/^\d+$/.test(value)) return { telegram_id: value, username: null };
            if (/^@[A-Za-z0-9_]{5,32}$/.test(value)) return { telegram_id: null, username: value };
            return null;
        }

        function fillKnownUserSelect(select) {
            if (!select) return;
            const selectedId = select.value;
            select.innerHTML = "";
            const empty = document.createElement("option");
            empty.value = "";
            empty.textContent = "Выбрать из тех, кто открывал бота или приложение";
            select.appendChild(empty);
            (Array.isArray(workState.knownUsers) ? workState.knownUsers : []).forEach((user) => {
                const username = String(user?.username || "").replace(/^@/, "");
                const option = document.createElement("option");
                option.value = String(user.id);
                option.textContent = user.name || (username ? `@${username}` : `Пользователь #${user.id}`);
                option.dataset.metaTop = username ? `@${username}` : "без username";
                const sourceLabel = { app: "открыл приложение", bot: "писал боту" }[String(user?.source || "")] || "";
                option.dataset.metaBottom = [`ID ${user.telegram_id || "—"}`, sourceLabel].filter(Boolean).join(" · ");
                select.appendChild(option);
            });
            if (selectedId && Array.from(select.options).some((option) => option.value === selectedId)) {
                select.value = selectedId;
            }
        }

        function renderUserCreateOptions() {
            fillKnownUserSelect(workUserExistingSelectEl);
            fillKnownUserSelect(workMemberExistingSelectEl);
        }

        function updateUserCreateMode() {
            const mode = String(workUserCreateModeEl?.value || "existing");
            workUserExistingWrapEl?.classList.toggle("hidden", mode !== "existing");
            workUserIdentityWrapEl?.classList.toggle("hidden", mode === "existing");
        }

        function updateUserCreateType() {
            const isFamilyAdmin = String(workUserSubscriptionTypeEl?.value || "") === "family_admin";
            workUserMembersCardEl?.classList.toggle("hidden", !isFamilyAdmin);
        }

        function updateMemberMode() {
            const mode = String(workMemberModeEl?.value || "existing");
            workMemberExistingWrapEl?.classList.toggle("hidden", mode !== "existing");
            workMemberIdentityWrapEl?.classList.toggle("hidden", mode === "existing");
            workMemberIdentityFieldEl?.classList.toggle("hidden", mode !== "new");
            if (workMemberNameLabelEl) {
                workMemberNameLabelEl.innerHTML = mode === "placeholder"
                    ? "Имя пустого места"
                    : 'Имя <span class="field-optional">необязательно</span>';
            }
        }

        function renderStagedBindings(listEl, bindings) {
            if (!listEl) return;
            listEl.innerHTML = "";
            if (!bindings.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Пока ничего не привязано. Нажми «+».";
                listEl.appendChild(empty);
                return;
            }
            bindings.forEach((binding, idx) => {
                const row = document.createElement("div");
                row.className = "binding-row";
                const text = document.createElement("div");
                text.className = "binding-row-text";
                const title = document.createElement("div");
                title.className = "binding-row-title";
                title.textContent = binding.label || binding.client_identifier;
                const sub = document.createElement("div");
                sub.className = "binding-row-sub";
                const inboundCount = Number(binding.inbound_count);
                sub.textContent = [
                    binding.server_name,
                    Number.isFinite(inboundCount) ? `Кол-во подключений: ${inboundCount}` : "",
                ].filter(Boolean).join(" · ");
                text.appendChild(title);
                text.appendChild(sub);
                const remove = document.createElement("button");
                remove.type = "button";
                remove.className = "binding-row-remove";
                remove.setAttribute("aria-label", "Убрать");
                remove.textContent = "×";
                remove.addEventListener("click", () => {
                    bindings.splice(idx, 1);
                    renderStagedBindings(listEl, bindings);
                });
                row.appendChild(text);
                row.appendChild(remove);
                listEl.appendChild(row);
            });
        }

        function renderStagedMembers() {
            if (!workUserMembersListEl) return;
            workUserMembersListEl.innerHTML = "";
            if (!createDraft.members.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = "Участников пока нет. Нажми «+».";
                workUserMembersListEl.appendChild(empty);
                return;
            }
            const modeLabels = { existing: "из бота", new: "новый", placeholder: "пустое место" };
            createDraft.members.forEach((member, idx) => {
                const row = document.createElement("div");
                row.className = "binding-row";
                const text = document.createElement("div");
                text.className = "binding-row-text";
                const title = document.createElement("div");
                title.className = "binding-row-title";
                title.textContent = member.title;
                const sub = document.createElement("div");
                sub.className = "binding-row-sub";
                const parts = [modeLabels[member.mode] || ""];
                if (member.bindings.length) parts.push(`подписок: ${member.bindings.length}`);
                sub.textContent = parts.filter(Boolean).join(" · ");
                text.appendChild(title);
                text.appendChild(sub);
                const remove = document.createElement("button");
                remove.type = "button";
                remove.className = "binding-row-remove";
                remove.setAttribute("aria-label", "Убрать участника");
                remove.textContent = "×";
                remove.addEventListener("click", () => {
                    createDraft.members.splice(idx, 1);
                    renderStagedMembers();
                });
                row.appendChild(text);
                row.appendChild(remove);
                workUserMembersListEl.appendChild(row);
            });
        }

        function resetUserCreateForm() {
            createDraft.bindings = [];
            createDraft.members = [];
            [
                workUserIdentityEl, workUserNameEl, workUserMonthPriceEl, workUserPaymentDateEl,
                workUserPaymentDetailsEl, workUserNotesEl,
            ].forEach((el) => {
                if (el) el.value = "";
            });
            if (workUserCreateModeEl) workUserCreateModeEl.value = "existing";
            if (workUserSubscriptionTypeEl) workUserSubscriptionTypeEl.value = "personal";
            renderUserCreateOptions();
            if (workUserExistingSelectEl) workUserExistingSelectEl.value = "";
            updateUserCreateMode();
            updateUserCreateType();
            renderStagedBindings(workUserBindingsListEl, createDraft.bindings);
            renderStagedMembers();
            setFormNote(workUserCreateStatusEl, "");
        }

        function resetMemberForm() {
            memberDraft.bindings = [];
            if (workMemberNotesEl) workMemberNotesEl.value = "";
            [workMemberIdentityEl, workMemberNameEl].forEach((el) => {
                if (el) el.value = "";
            });
            if (workMemberModeEl) workMemberModeEl.value = "existing";
            renderUserCreateOptions();
            if (workMemberExistingSelectEl) workMemberExistingSelectEl.value = "";
            updateMemberMode();
            renderStagedBindings(workMemberBindingsListEl, memberDraft.bindings);
            setFormNote(workMemberStatusEl, "");
        }

        function serverGroupsFromInbounds() {
            const groups = new Map();
            (Array.isArray(workState.inbounds) ? workState.inbounds : []).forEach((inbound) => {
                const key = String(inbound?.panel_id ?? inbound?.panel_name ?? "");
                if (!groups.has(key)) {
                    groups.set(key, {
                        id: key,
                        name: String(inbound?.panel_name || "").trim() || "Сервер",
                        region: String(inbound?.region || "").trim(),
                        inbounds: [],
                    });
                }
                groups.get(key).inbounds.push(inbound);
            });
            return Array.from(groups.values());
        }

        /** Шаг 1: выбираем сервер. Шаг 2: выбираем пользователя на этом сервере. */
        async function pickServerBinding() {
            const servers = serverGroupsFromInbounds();
            if (!servers.length) {
                throw new Error("Серверов с подключениями пока нет. Добавь сервер во вкладке «Сервера».");
            }
            const serverKey = await openUiSheet({
                title: "Выбери сервер",
                items: servers.map((server) => ({
                    value: server.id,
                    label: server.name,
                    meta: [server.region ? server.region.toUpperCase() : "", `подключений: ${server.inbounds.length}`],
                })),
            });
            if (serverKey === null) return null;
            const server = servers.find((item) => item.id === serverKey);
            if (!server) return null;

            // Единый список клиентов панели одним запросом (Clients API)
            // вместо отдельного запроса на каждый inbound.
            let resp;
            try {
                resp = await fetchJson(adminPanelClientsUrl, false);
            } catch (err) {
                console.error("load panel clients error:", err);
                throw new Error("Не удалось загрузить клиентов панели. Проверь, что панель поддерживает Clients API и доступна.");
            }
            const allClients = Array.isArray(resp?.clients) ? resp.clients : [];
            const panelIds = new Set(server.inbounds.map((inbound) => String(inbound.panel_id ?? "")));
            const rows = allClients.filter((client) => panelIds.has(String(client?.panel_id ?? "")));
            if (!rows.length) {
                throw new Error(`На сервере «${server.name}» нет клиентов. Попробуй «Обновить список с серверов».`);
            }
            const pickedIdx = await openUiSheet({
                title: `Клиент на «${server.name}»`,
                searchable: true,
                items: rows.map((client, idx) => ({
                    value: String(idx),
                    label: client.email || client.comment || "Клиент",
                    meta: [
                        client.panel_name || "",
                        client.bound ? "привязан" : `Подключений: ${(client.inbound_ids || []).length}`,
                    ],
                })),
            });
            if (pickedIdx === null) return null;
            const client = rows[Number(pickedIdx)];
            if (!client) return null;
            const firstInboundId = (client.inbound_ids || [])[0];
            const inbound = server.inbounds.find((item) => String(item.panel_inbound_id) === String(firstInboundId)) || server.inbounds[0];
            return {
                panel_id: client.panel_id,
                email: client.email,
                client_identifier: client.email,
                protocol: String(inbound?.protocol || "vless").toLowerCase(),
                label: client.comment || client.email,
                sub_id: client.sub_id ?? null,
                server_name: server.name,
                inbound_name: inbound?.remark || "",
                inbound_count: Array.isArray(client.inbound_ids) ? client.inbound_ids.length : 0,
            };
        }

        function bindingRequestBody(userId, binding) {
            return {
                user_id: Number(userId),
                panel_inbound_ref_id: binding.panel_inbound_ref_id,
                client_identifier: binding.client_identifier,
                protocol: binding.protocol,
                label: binding.label,
                secret: binding.secret,
                sub_id: binding.sub_id,
                inbound_ids: Array.isArray(binding.inbound_ids) ? binding.inbound_ids : [],
            };
        }

        /** Привязка binding к пользователю: Clients API-путь (/panel-client),
         * если выбран клиент панели (известен panel_id), иначе — старый
         * per-inbound путь (/bind-client). */
        async function postBinding(userId, binding) {
            if (binding && binding.panel_id) {
                return postJson(adminUserPanelClientUrl(userId), {
                    panel_id: binding.panel_id,
                    email: binding.client_identifier,
                });
            }
            return postJson(adminBindClientUrl, bindingRequestBody(userId, binding));
        }

        async function addStagedBinding(bindings, listEl, statusEl) {
            try {
                const picked = await pickServerBinding();
                if (!picked) return;
                const duplicate = bindings.some((item) =>
                    item.client_identifier === picked.client_identifier
                    && String(item.panel_id ?? "") === String(picked.panel_id ?? "")
                );
                if (duplicate) {
                    setFormNote(statusEl, "Эта подписка уже добавлена", "error");
                    return;
                }
                bindings.push(picked);
                renderStagedBindings(listEl, bindings);
                setFormNote(statusEl, "");
            } catch (err) {
                setFormNote(statusEl, err?.message || "Не удалось выбрать подписку", "error");
            }
        }

        async function saveMemberDraft() {
            const liveGroup = memberPageGroup;
            try {
                const mode = String(workMemberModeEl?.value || "existing");
                const member = {
                    mode,
                    bindings: memberDraft.bindings.slice(),
                    notes: String(workMemberNotesEl?.value || "").trim(),
                };
                if (mode === "existing") {
                    const userId = Number(workMemberExistingSelectEl?.value || 0);
                    if (!userId) throw new Error("Выбери пользователя из списка");
                    if (liveGroup) {
                        const inGroup = (liveGroup.members || []).some((m) => Number(m.id) === userId)
                            || userId === Number(workState.selectedUserId);
                        if (inGroup) throw new Error("Этот пользователь уже в группе");
                    } else if (createDraft.members.some((item) => item.mode === "existing" && item.user_id === userId)) {
                        throw new Error("Этот пользователь уже добавлен");
                    }
                    const option = workMemberExistingSelectEl.options[workMemberExistingSelectEl.selectedIndex];
                    member.user_id = userId;
                    member.title = option?.textContent || `Пользователь #${userId}`;
                } else if (mode === "new") {
                    const identity = parseTelegramIdentity(workMemberIdentityEl?.value);
                    if (!identity) throw new Error("Укажи числовой Telegram ID или username с @");
                    member.telegram_id = identity.telegram_id;
                    member.username = identity.username;
                    member.name = String(workMemberNameEl?.value || "").trim();
                    member.title = member.name || member.username || `ID ${member.telegram_id}`;
                } else {
                    const name = String(workMemberNameEl?.value || "").trim();
                    if (!name) throw new Error("Укажи имя пустого места");
                    member.name = name;
                    member.title = name;
                }
                if (liveGroup) {
                    if (workMemberSaveEl) workMemberSaveEl.disabled = true;
                    setFormNote(workMemberStatusEl, "Добавляем участника…");
                    try {
                        await createGroupMember(member, liveGroup.id);
                    } finally {
                        if (workMemberSaveEl) workMemberSaveEl.disabled = false;
                        await loadSelectedUserOverview().catch(() => {});
                        await loadWorkClientsData().catch(() => {});
                    }
                    setFormNote(workMemberStatusEl, "");
                    memberPageGroup = null;
                    switchWorkPage("work-client-group-page");
                    setWorkGroupStatus(`Участник добавлен: ${member.title}`, "success");
                    return;
                }
                createDraft.members.push(member);
                renderStagedMembers();
                switchWorkPage("work-user-create-page");
            } catch (err) {
                setFormNote(workMemberStatusEl, err?.message || "Не удалось добавить участника", "error");
            }
        }

        async function createGroupMember(member, groupId) {
            const base = { subscription_type: "family_member", group_id: groupId };
            // Заметки отправляем только если они есть: иначе у существующего клиента они бы стёрлись.
            if (member.notes) base.notes = member.notes;
            let userId;
            if (member.mode === "existing") {
                const result = await postJson(adminUserSubscriptionUrl(member.user_id), base);
                userId = result?.overview?.user?.id || member.user_id;
            } else {
                const result = await postJson(adminUsersUrl, {
                    ...base,
                    name: member.name || null,
                    telegram_id: member.telegram_id || null,
                    username: member.username || null,
                    allow_placeholder: member.mode === "placeholder",
                });
                userId = result?.user?.id;
            }
            for (const binding of member.bindings) {
                await postBinding(userId, binding);
            }
            return userId;
        }

        async function submitUserCreate() {
            if (!workUserCreateSubmitEl) return;
            workUserCreateSubmitEl.disabled = true;
            setFormNote(workUserCreateStatusEl, "Сохраняем пользователя…");
            try {
                const mode = String(workUserCreateModeEl?.value || "existing");
                const type = String(workUserSubscriptionTypeEl?.value || "personal");
                const date = String(workUserPaymentDateEl?.value || "").trim();
                const payload = {
                    price_amount: String(workUserMonthPriceEl?.value || "").trim() || null,
                    billing_day: date ? Number(date.slice(-2)) : null,
                    billing_details: String(workUserPaymentDetailsEl?.value || "").trim() || null,
                    notes: String(workUserNotesEl?.value || "").trim() || null,
                    subscription_type: type,
                };
                if (date) payload.access_until = `${date}T23:55:00`; // действует весь выбранный день

                let userId;
                let groupId = null;
                if (mode === "existing") {
                    userId = Number(workUserExistingSelectEl?.value || 0);
                    if (!userId) throw new Error("Выбери пользователя из списка");
                    const result = await postJson(adminUserSubscriptionUrl(userId), payload);
                    groupId = result?.overview?.user?.group_id || null;
                } else {
                    const identity = parseTelegramIdentity(workUserIdentityEl?.value);
                    if (!identity) throw new Error("Укажи числовой Telegram ID или username с @");
                    const result = await postJson(adminUsersUrl, {
                        ...payload,
                        name: String(workUserNameEl?.value || "").trim() || null,
                        telegram_id: identity.telegram_id,
                        username: identity.username,
                    });
                    userId = result?.user?.id;
                    groupId = result?.user?.group_id || null;
                }

                const failures = [];
                for (const binding of createDraft.bindings) {
                    try {
                        await postBinding(userId, binding);
                    } catch (err) {
                        failures.push(`${binding.label || binding.client_identifier}: ${err?.message || "ошибка"}`);
                    }
                }
                if (type === "family_admin") {
                    for (const member of createDraft.members) {
                        if (!groupId) {
                            failures.push("группа семьи не создана, участники не добавлены");
                            break;
                        }
                        try {
                            await createGroupMember(member, groupId);
                        } catch (err) {
                            failures.push(`${member.title}: ${err?.message || "ошибка"}`);
                        }
                    }
                }

                await loadWorkClientsData();
                if (applicationMode) {
                    // Заявка: клиент настроен формой, теперь подтверждаем её и сообщаем клиенту.
                    const application = applicationMode;
                    let note = "Заявка подтверждена, клиент получил сообщение";
                    let tone = "success";
                    try {
                        const result = await postJson(`${adminApplicationsUrl}/${application.id}/approve`, {
                            message: String(workAppReplyEl?.value || "").trim(),
                        });
                        if (!result?.notified) note = "Заявка подтверждена, но сообщение клиенту отправить не удалось";
                    } catch (err) {
                        note = `Клиент настроен, но заявку подтвердить не удалось: ${err?.message || "ошибка"}`;
                        tone = "error";
                    }
                    if (failures.length) {
                        note += `. Не всё применилось: ${failures.join("; ")}`;
                        tone = "error";
                    }
                    setApplicationMode(null);
                    switchWorkPage("work-applications-page");
                    setFormNote(workApplicationsStatusEl, note, tone);
                    return;
                }
                if (userId) await openWorkClientPage(userId);
                if (failures.length) {
                    setFormNote(
                        workClientActionStatusEl,
                        `Пользователь создан, но не всё применилось: ${failures.join("; ")}`,
                        "error"
                    );
                }
            } catch (err) {
                setFormNote(workUserCreateStatusEl, err?.message || "Не удалось сохранить пользователя", "error");
            } finally {
                workUserCreateSubmitEl.disabled = false;
            }
        }

        /** «Семья Иван» вместо «Семья 1»: по имени администратора группы. */
        function workGroupLabel(group, adminNameHint = "") {
            const adminId = String(group?.admin_user_id ?? "");
            const adminUser = adminId ? (workState.users || []).find((u) => String(u.id) === adminId) : null;
            const adminMember = (group?.members || []).find((m) => m?.is_admin);
            const adminName = String(
                adminNameHint || adminUser?.name || adminUser?.username || adminMember?.name || adminMember?.username || ""
            ).trim();
            return adminName ? `Семья ${adminName}` : (group?.name || `Семья #${group?.id}`);
        }

        function renderUserCreateGroups() {
            if (!workSubGroupSelectEl) return;
            const selectedId = workSubGroupSelectEl.value;
            workSubGroupSelectEl.innerHTML = '<option value="">Выберите семью</option>';
            (Array.isArray(workState.groups) ? workState.groups : []).forEach((group) => {
                const option = document.createElement("option");
                option.value = String(group.id);
                option.textContent = workGroupLabel(group);
                const membersCount = Array.isArray(group.members) ? group.members.length : Number(group.members_count || 0);
                if (membersCount) option.dataset.metaBottom = `Участников: ${membersCount}`;
                workSubGroupSelectEl.appendChild(option);
            });
            if (workState.groups.some((group) => String(group.id) === selectedId)) {
                workSubGroupSelectEl.value = selectedId;
            }
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

        async function openWorkInboundDetail(panelInboundRefIdRaw, backPage = "work-panel-detail-page") {
            const panelInboundRefId = Number(panelInboundRefIdRaw || 0);
            if (!panelInboundRefId) return;
            const inboundBackBtn = document.querySelector("#work-inbound-detail-page .work-back-btn");
            if (inboundBackBtn) inboundBackBtn.dataset.workBack = backPage;
            workBackTargetByPage.set("work-inbound-detail-page", backPage);
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
            // Статус дублируется во всплывающем окне доступа, иначе за оверлеем его не видно.
            [workPanelDetailStatusEl, workPanelAccessStatusEl].forEach((el) => {
                if (!el) return;
                el.classList.remove("success", "error");
                if (!message) {
                    el.textContent = "";
                    el.classList.add("hidden");
                    return;
                }
                if (tone === "success" || tone === "error") {
                    el.classList.add(tone);
                }
                el.textContent = message;
                el.classList.remove("hidden");
            });
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
            const token = String(workPanelTokenEl?.value || "").trim().replace(/^bearer\s+/i, "");
            return {
                name: String(workPanelNameEl?.value || "").trim(),
                provider: String(workPanelProviderEl?.value || "3xui").trim(),
                base_url: String(workPanelBaseUrlEl?.value || "").trim(),
                region: String(workPanelRegionEl?.value || "").trim() || null,
                auth_type: token ? "api_token" : "login_password",
                token,
                token_header: "Authorization",
                token_prefix: "Bearer",
                username: String(workPanelUsernameEl?.value || "").trim(),
                password: String(workPanelPasswordEl?.value || "").trim(),
            };
        }

        function collectWorkPanelDetailAccessPayload() {
            return {
                base_url: String(workPanelDetailBaseUrlEl?.value || "").trim(),
                token: String(workPanelDetailTokenEl?.value || "").trim().replace(/^bearer\s+/i, ""),
                token_header: "Authorization",
                token_prefix: "Bearer",
                username: String(workPanelDetailUsernameEl?.value || "").trim(),
                password: String(workPanelDetailPasswordEl?.value || "").trim(),
            };
        }

        function isPanelAccessModalOpen() {
            return Boolean(workPanelAccessOverlayEl && !workPanelAccessOverlayEl.classList.contains("hidden"));
        }

        function isWorkSheetOpen() {
            return [
                workPanelAccessOverlayEl, workClientActionsOverlayEl, workClientExtendOverlayEl,
                workClientIdentityOverlayEl, workClientsFiltersOverlayEl,
            ].some((el) => el && !el.classList.contains("hidden")) || isCenterModalOpen();
        }

        function setWorkSheetVisible(overlayEl, visible) {
            if (!overlayEl) return;
            overlayEl.classList.toggle("hidden", !visible);
            overlayEl.setAttribute("aria-hidden", visible ? "false" : "true");
            document.body.classList.toggle("ui-sheet-open", isWorkSheetOpen() || isUiSheetOpen());
            updateTelegramBackButton();
            if (fullscreenSheetTitles.has(overlayEl)) {
                workContextOverrideTitle = visible ? fullscreenSheetTitles.get(overlayEl) : "";
                updateWorkPageContext(getActiveWorkPageId());
            }
        }

        // В Telegram окно «Действия» закрывается системной кнопкой «назад»; крестик нужен
        // только в браузере (без Telegram), поэтому там, где он не нужен, прячем его.
        if (window.Telegram?.WebApp?.initData) {
            workClientActionsCloseEl?.classList.add("hidden");
            workClientActionsOverlayEl?.classList.add("ui-sheet-overlay-tg");
            workClientIdentityCloseEl?.classList.add("hidden");
            workClientIdentityOverlayEl?.classList.add("ui-sheet-overlay-tg");
            workClientsFiltersCloseEl?.classList.add("hidden");
            workClientsFiltersOverlayEl?.classList.add("ui-sheet-overlay-tg");
        }

        function closeWorkSheets() {
            toggleWorkPanelAccessSection(false);
            setWorkSheetVisible(workClientActionsOverlayEl, false);
            setWorkSheetVisible(workClientExtendOverlayEl, false);
            setWorkSheetVisible(workClientIdentityOverlayEl, false);
            setWorkSheetVisible(workClientsFiltersOverlayEl, false);
            closeCenterModal("cancel");
        }

        /** Настройки доступа открываются отдельным всплывающим окном (а не списком вниз по странице). */
        function toggleWorkPanelAccessSection(forceVisible = null) {
            if (!workPanelAccessOverlayEl) return;
            const nextVisible = forceVisible === null ? !isPanelAccessModalOpen() : Boolean(forceVisible);
            setWorkSheetVisible(workPanelAccessOverlayEl, nextVisible);
            if (!nextVisible && workPanelAccessStatusEl) {
                workPanelAccessStatusEl.textContent = "";
                workPanelAccessStatusEl.classList.add("hidden");
            }
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
                    openWorkInboundDetail(panelInboundRefId, "work-panel-inbounds-page").catch((err) => {
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
            const health = String(panel?.health_status || "unknown").trim().toLowerCase() || "unknown";
            const panelInbounds = getWorkPanelInbounds(panel.id);

            if (workPanelDetailTitleEl) {
                workPanelDetailTitleEl.textContent = `${panelName}${region ? ` (${region})` : ""}`;
            }

            if (workPanelDetailSummaryEl) {
                workPanelDetailSummaryEl.innerHTML = "";
                // Компактные плитки: несколько в одну строку. Провайдер, метрики и
                // дубли (health/«Панель: on») на этой странице не показываем.
                const tileRows = [
                    {
                        cls: "name-region",
                        tiles: [
                            ["Название", panelName],
                            ["Локация", (region || "—").toUpperCase()],
                        ],
                    },
                    {
                        cls: "triple",
                        tiles: [
                            ["Состояние", health],
                            ["Активность", panel?.is_active ? "active" : "inactive"],
                            ["Подключения", String(panelInbounds.length)],
                        ],
                    },
                    {
                        cls: "single",
                        tiles: [["Последняя успешная проверка", panel?.last_ok_at ? fmtDateTime(panel.last_ok_at) : "—"]],
                    },
                ];
                if (panel?.error_message) {
                    tileRows.push({ cls: "single", tiles: [["Последняя ошибка", String(panel.error_message).trim()]] });
                }
                tileRows.forEach((tileRow) => {
                    const rowEl = document.createElement("div");
                    rowEl.className = `work-panel-tiles-row ${tileRow.cls}`;
                    tileRow.tiles.forEach(([label, value]) => {
                        const tile = document.createElement("div");
                        tile.className = "work-link-item work-panel-tile";
                        const labelEl = document.createElement("div");
                        labelEl.className = "work-panel-tile-label";
                        labelEl.textContent = label;
                        const valueEl = document.createElement("div");
                        valueEl.className = "work-panel-tile-value";
                        valueEl.textContent = value || "—";
                        tile.appendChild(labelEl);
                        tile.appendChild(valueEl);
                        rowEl.appendChild(tile);
                    });
                    workPanelDetailSummaryEl.appendChild(rowEl);
                });
            }

            // Кнопка «Активировать/Деактивировать» убрана с экрана, но функционал
            // (toggleWorkPanelActive) остаётся: если кнопку вернут в разметку, она заработает.
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

        /** Метрики сервера (CPU/RAM/диск/uptime). С экрана панели временно убраны, функция оставлена. */
        async function loadWorkPanelMetrics(panelId) {
            const response = await fetchJson(adminPanelMetricsUrl(panelId), false);
            return String(response?.text || "Метрики недоступны.");
        }

        function openWorkPanelInbounds() {
            const panelId = String(workState.selectedPanelId || "").trim();
            if (!panelId) return;
            renderWorkPanelInbounds(panelId);
            switchWorkPage("work-panel-inbounds-page");
        }

        function setWorkPanelClientsStatus(message, tone = "") {
            if (!workPanelClientsStatusEl) return;
            workPanelClientsStatusEl.classList.remove("success", "error");
            if (!message) {
                workPanelClientsStatusEl.textContent = "";
                workPanelClientsStatusEl.classList.add("hidden");
                return;
            }
            if (tone === "success" || tone === "error") workPanelClientsStatusEl.classList.add(tone);
            workPanelClientsStatusEl.textContent = message;
            workPanelClientsStatusEl.classList.remove("hidden");
        }

        function renderWorkPanelClients(rows, emptyText = "На этом сервере пока нет клиентов.") {
            if (!workPanelClientsListEl) return;
            workPanelClientsListEl.innerHTML = "";
            if (!rows.length) {
                const empty = document.createElement("div");
                empty.className = "work-empty";
                empty.textContent = emptyText;
                workPanelClientsListEl.appendChild(empty);
                return;
            }
            rows.forEach((client) => {
                const item = document.createElement("div");
                item.className = "work-link-item";
                const title = document.createElement("div");
                title.className = "work-link-item-title";
                title.textContent = String(client?.email || client?.comment || "Клиент");
                const count = document.createElement("div");
                count.className = "work-link-item-sub";
                count.textContent = `Кол-во подключений: ${Array.isArray(client?.inbound_ids) ? client.inbound_ids.length : 0}`;
                const state = document.createElement("div");
                state.className = "work-link-item-sub";
                state.textContent = [
                    client?.enable === false ? "отключён" : "активен",
                    client?.bound ? "привязан к пользователю" : "не привязан",
                ].join(" • ");
                item.appendChild(title);
                item.appendChild(count);
                item.appendChild(state);
                workPanelClientsListEl.appendChild(item);
            });
        }

        async function openWorkPanelClients() {
            const panelId = String(workState.selectedPanelId || "").trim();
            if (!panelId) return;
            setWorkPanelClientsStatus("");
            renderWorkPanelClients([], "Загрузка клиентов...");
            switchWorkPage("work-panel-clients-page");
            try {
                const resp = await fetchJson(`${adminPanelClientsUrl}?panel_id=${encodeURIComponent(panelId)}`, false);
                if (String(workState.selectedPanelId || "") !== panelId) return;
                const rows = (Array.isArray(resp?.clients) ? resp.clients : [])
                    .filter((client) => String(client?.panel_id ?? "") === panelId)
                    .sort((a, b) => String(a?.email || "").localeCompare(String(b?.email || "")));
                const panelError = (Array.isArray(resp?.errors) ? resp.errors : [])
                    .find((row) => String(row?.panel_id ?? "") === panelId);
                renderWorkPanelClients(rows);
                if (!rows.length && panelError) {
                    setWorkPanelClientsStatus(`Не удалось получить клиентов с сервера: ${panelError.error || "ошибка"}`, "error");
                }
            } catch (err) {
                console.error("load panel clients error:", err);
                renderWorkPanelClients([], "Не удалось загрузить клиентов.");
                setWorkPanelClientsStatus(err?.message || "Не удалось загрузить клиентов", "error");
            }
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
            if (!payload.token && (!payload.username || !payload.password)) {
                throw new Error("Для проверки укажи login и password");
            }
            return postJson(adminPanelsTestUrl, {
                name: String(panel?.name || "Panel").trim() || "Panel",
                provider: String(panel?.provider || "3xui").trim() || "3xui",
                base_url: baseUrl,
                auth_type: payload.token ? "api_token" : "login_password",
                token: payload.token,
                token_header: payload.token_header,
                token_prefix: payload.token_prefix,
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

            const hasToken = Boolean(payload.token);
            const hasUsername = Boolean(payload.username);
            const hasPassword = Boolean(payload.password);
            if (hasToken && (hasUsername || hasPassword)) {
                throw new Error("Укажи API-токен или пару login/password");
            }
            if (hasUsername !== hasPassword) {
                throw new Error("Укажи и login, и password");
            }
            if (hasToken || (hasUsername && hasPassword)) {
                await postJson(adminPanelActionUrl(panel.id, "rotate-secret"), {
                    auth_type: hasToken ? "api_token" : "login_password",
                    token: payload.token,
                    token_header: payload.token_header,
                    token_prefix: payload.token_prefix,
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
            if (!/^[a-z]{2}$/i.test(payload.region || "")) {
                throw new Error("Укажи двухбуквенный код локации, например de");
            }
            await postJson(adminPanelsTestUrl, payload);
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

        
        function setWorkClientRoleStatus(message, tone = "") {
            if (!workClientRoleStatusEl) return;
            workClientRoleStatusEl.classList.remove("success", "error");
            if (!message) {
                workClientRoleStatusEl.textContent = "";
                workClientRoleStatusEl.classList.add("hidden");
                return;
            }
            if (tone === "success" || tone === "error") {
                workClientRoleStatusEl.classList.add(tone);
            }
            workClientRoleStatusEl.textContent = message;
            workClientRoleStatusEl.classList.remove("hidden");
        }

        function renderWorkClientOverview(overview) {
            workState.overview = overview || null;
            const sub = overview?.subscription || null;
            const role = String(overview?.user?.role || "user").trim().toLowerCase();

            if (workSubPriceInputEl) {
                workSubPriceInputEl.value = sub?.price_amount ?? "";
            }
            if (workSubBillingDayEl) {
                workSubBillingDayEl.value = sub?.billing_day ?? "";
            }
            if (workSubBillingDetailsEl) {
                workSubBillingDetailsEl.value = sub?.billing_details ?? "";
            }
            if (workSubNotesEl) {
                workSubNotesEl.value = sub?.notes ?? "";
            }
            if (workSubscriptionTypeSelectEl) {
                workSubscriptionTypeSelectEl.value = overview?.user?.subscription_type || "personal";
            }
            if (workSubGroupSelectEl) {
                workSubGroupSelectEl.value = overview?.user?.group_id ? String(overview.user.group_id) : "";
            }
            workSubGroupWrapEl?.classList.toggle(
                "hidden",
                workSubscriptionTypeSelectEl?.value !== "family_member"
            );
            if (workClientRoleSelectEl) {
                workClientRoleSelectEl.value = role || "user";
            }
            setWorkClientRoleStatus("");
            renderWorkSubscriptionControls(sub);

            const viaAdmin = isWorkClientGroupMember(overview);
            const adminSub = viaAdmin ? (overview?.group?.admin_subscription || null) : null;
            // Участник группы без своей записи подписки живёт по подписке администратора.
            const statusViaAdmin = Boolean(viaAdmin && !sub && adminSub);
            workClientSubStatusEl.textContent = subscriptionStatusLabel(statusViaAdmin ? adminSub : sub);
            // Участник группы платит через администратора: срок и цену берём у него (плитки зелёные).
            workClientSubUntilEl.textContent = viaAdmin
                ? (adminSub ? formatSubscriptionUntil(adminSub, fmtDateOnly) : "—")
                : formatSubscriptionUntil(sub, fmtDateOnly);
            workClientSubPriceEl.textContent = viaAdmin ? fmtMoney(adminSub?.price_amount) : fmtMoney(sub?.price_amount);
            [workClientSubUntilEl, workClientSubPriceEl].forEach((el) => {
                el.closest(".work-panel-tile")?.classList.toggle("work-panel-tile-green", viaAdmin);
            });
            workClientSubStatusEl.closest(".work-panel-tile")?.classList.toggle("work-panel-tile-green", statusViaAdmin);
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
                if (workClientRoleSelectEl) {
                    workClientRoleSelectEl.value = "user";
                }
                setWorkClientRoleStatus("");
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
            workClientMetaEl.textContent = [
                user.id,
                user.username ? `@${user.username}` : "—",
                user.telegram_id ? `TG ${user.telegram_id}` : "",
            ].filter(Boolean).join(" · ");
            if (workClientRoleSelectEl) {
                workClientRoleSelectEl.value = String(user.role || "user").toLowerCase();
            }
            if (workClientFreezeBtnEl) {
                workClientFreezeBtnEl.textContent = workState.overview?.subscription?.is_frozen
                    ? "Разморозить пользователя"
                    : "Заморозить пользователя";
            }
            setWorkClientRoleStatus("");
        }

        async function loadWorkClientsData() {
            const [usersResp, inboundsResp, groupsResp, knownUsersResp] = await Promise.all([
                fetchJson(adminUsersUrl, false),
                fetchJson(adminInboundsUrl, false),
                fetchJson(adminGroupsUrl, false),
                fetchJson(adminKnownUsersUrl, false),
            ]);
            workState.users = Array.isArray(usersResp?.users) ? usersResp.users : [];
            workState.inbounds = Array.isArray(inboundsResp?.inbounds) ? inboundsResp.inbounds : [];
            workState.groups = Array.isArray(groupsResp?.data) ? groupsResp.data : [];
            workState.knownUsers = Array.isArray(knownUsersResp?.users) ? knownUsersResp.users : [];
            renderWorkClientCards();
            renderUserCreateOptions();
            renderUserCreateGroups();
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
            workState.clients = [];
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
            
            await Promise.all([
                loadSelectedUserBindings(),
                loadSelectedUserOverview(),
                
                
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
            await postJson(adminSyncInboundsUrl);
            const inboundsResp = await fetchJson(adminInboundsUrl, false);
            workState.inbounds = Array.isArray(inboundsResp?.inbounds) ? inboundsResp.inbounds : [];
            renderWorkInboundsManager();
            renderWorkInboundSelectOptions();
            renderWorkPendingInboundSelectOptions();
            return { inbounds: workState.inbounds.length };
        }


        async function switchWorkPage(target) {
            closeWorkSheets();
            let next = target || "work-menu-page";
            if (adminOnlyMode && next === "work-menu-page") {
                next = "work-clients-page";
            }
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
            if (applicationMode && !["work-user-create-page", "work-user-member-page"].includes(next)) {
                setApplicationMode(null);  // вышли из рассмотрения заявки - форма снова обычная
            }
            if (next === "work-user-create-page" && current !== "work-user-member-page") {
                if (applicationMode && current !== "work-applications-page") setApplicationMode(null);
                resetUserCreateForm();
            }
            if (next === "work-user-member-page" && current !== "work-user-member-page") {
                resetMemberForm();
            }
            workPages.forEach((page) => page.classList.toggle("hidden", page.id !== next));
            if (adminOnlyMode) {
                const activeTab = next.includes("panel") || next.includes("inbound")
                    ? "work-panels-page"
                    : (next === "work-admin-page" || next.startsWith("work-broadcast") || next.startsWith("work-finance")
                        || next === "work-applications-page" || (applicationMode && next.startsWith("work-user-")))
                        ? "work-admin-page"
                        : "work-clients-page";
                adminPageButtons.forEach((button) => {
                    button.classList.toggle("active", button.dataset.adminPage === activeTab);
                });
                // На экране выбора получателей вместо вкладок - панель [Выделить всех] [Снять] [✓].
                const selecting = next === "work-broadcast-recipients-page";
                adminBottomNavEl?.classList.toggle("hidden", selecting);
                workSelectionBarEl?.classList.toggle("hidden", !selecting);
                if (selecting && current !== "work-broadcast-recipients-page") {
                    broadcastState.selected = new Set(broadcastState.recipientIds);
                    if (!(workState.users || []).length) {
                        loadWorkClientsData().then(renderRecipientList).catch((err) => console.error("load recipients error:", err));
                    }
                    renderRecipientList();
                }
                if (next === "work-broadcast-page") renderBroadcastPage();
                if (next === "work-admin-page") loadApplications({ quiet: true });
                if (next === "work-applications-page") loadApplications();
                if (next.startsWith("work-finance")) {
                    // Заходим на главную финансов - берём свежие цифры; на вложенных страницах хватает уже загруженных.
                    if (next === "work-finance-page" || !financeState.summary) loadFinanceSummary();
                    else renderFinance();
                }
            }
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
            if (adminOnlyMode && target !== "screen-work") {
                target = "screen-work";
            }
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
                if (!adminOnlyMode) {
                    switchWorkPage("work-menu-page");
                }
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
                const message = payload.error === "Invalid initData"
                    ? "Telegram не подтвердил запуск Mini App. Откройте его через кнопку в боте и попробуйте снова."
                    : payload.error || "Телеграм не подтвердил данные пользователя.";
                throw new Error(message);
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
        // Удержание капсулы на странице клиентов открывает фильтры, обычное нажатие обновляет список.
        let workPillPressTimer = null;
        let workPillLongPressFired = false;
        const stopPillPressing = () => setTimeout(() => document.body.classList.remove("pill-pressing"), 350);
        const cancelWorkPillPress = () => {
            if (workPillPressTimer) {
                clearTimeout(workPillPressTimer);
                workPillPressTimer = null;
            }
            stopPillPressing();
        };
        workPageContextPillEl?.addEventListener("pointerdown", () => {
            const pageId = getActiveWorkPageId();
            if (!filterContexts[pageId] || workContextOverrideTitle) return;
            workPillLongPressFired = false;
            cancelWorkPillPress();
            // Пока палец на капсуле, браузер не должен начинать выделять текст.
            document.body.classList.add("pill-pressing");
            workPillPressTimer = setTimeout(() => {
                workPillPressTimer = null;
                workPillLongPressFired = true;
                window.getSelection?.()?.removeAllRanges?.();
                window.Telegram?.WebApp?.HapticFeedback?.impactOccurred?.("medium");
                openClientFilters(pageId);
            }, 550);
        });
        ["pointerup", "pointerleave", "pointercancel"].forEach((name) => {
            workPageContextPillEl?.addEventListener(name, cancelWorkPillPress);
        });
        document.addEventListener("selectstart", (event) => {
            if (document.body.classList.contains("pill-pressing")) event.preventDefault();
        });
        workPageContextPillEl?.addEventListener("contextmenu", (event) => event.preventDefault());
        workPageContextPillEl?.addEventListener("click", () => {
            if (workPillLongPressFired) {  // это отпускание после долгого нажатия, обновлять не нужно
                workPillLongPressFired = false;
                return;
            }
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
            if (isWorkSheetOpen()) {
                closeWorkSheets();
                return;
            }
            if (getActiveScreenId() === "screen-work" && getActiveWorkPageId() === "work-inbound-detail-page") {
                switchWorkPage(workBackTargetByPage.get("work-inbound-detail-page") || "work-panel-detail-page");
                return;
            }
            if (
                getActiveScreenId() === "screen-work"
                && ["work-panel-inbounds-page", "work-panel-clients-page"].includes(getActiveWorkPageId())
            ) {
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

        function setWorkClientActionStatus(message, tone = "") {
            [workClientActionStatusEl, workClientActionsPopupStatusEl, workClientExtendPopupStatusEl].forEach((el) => {
                if (!el) return;
                el.classList.remove("success", "error");
                if (!message) {
                    el.textContent = "";
                    el.classList.add("hidden");
                    return;
                }
                if (tone === "success" || tone === "error") el.classList.add(tone);
                el.textContent = message;
                el.classList.remove("hidden");
            });
        }

        /** Выполняет действие над выбранным клиентом: блокирует повторные нажатия, показывает результат. */
        async function runWorkClientAction(action, { successText = "", errorText = "Не удалось выполнить действие", closeSheets = true } = {}) {
            const userId = Number(workState.selectedUserId || 0);
            if (!userId) return false;
            setWorkClientActionStatus("");
            try {
                await action(userId);
                if (closeSheets) closeWorkSheets();
                setWorkClientActionStatus(successText, "success");
                return true;
            } catch (err) {
                console.error("client action error:", err);
                setWorkClientActionStatus(err?.message || errorText, "error");
                return false;
            }
        }

        workClientActionsBtnEl?.addEventListener("click", () => {
            setWorkClientActionStatus("");
            renderWorkSubscriptionControls(workState.overview?.subscription || null);
            setWorkSheetVisible(workClientActionsOverlayEl, true);
        });
        workClientExtendBtnEl?.addEventListener("click", () => {
            setWorkClientActionStatus("");
            renderWorkSubscriptionControls(workState.overview?.subscription || null);
            setWorkSheetVisible(workClientExtendOverlayEl, true);
        });
        workClientActionsCloseEl?.addEventListener("click", () => setWorkSheetVisible(workClientActionsOverlayEl, false));
        workClientExtendCloseEl?.addEventListener("click", () => setWorkSheetVisible(workClientExtendOverlayEl, false));
        [workClientActionsOverlayEl, workClientExtendOverlayEl].forEach((overlay) => {
            overlay?.addEventListener("click", (event) => {
                if (event.target === overlay) setWorkSheetVisible(overlay, false);
            });
        });

        workClientStatusChipsEl?.addEventListener("click", async (event) => {
            const btn = event.target.closest("[data-sub-status]");
            if (!btn) return;
            const status = String(btn.dataset.subStatus || "");
            if (status === "frozen") {
                await toggleWorkClientFreeze();
                return;
            }
            const sub = workState.overview?.subscription || null;
            const label = SUBSCRIPTION_STATUS_LABELS[status] || status;
            if (!sub && status !== "lifetime") {
                setWorkClientActionStatus("Подписки пока нет. Сначала создайте её через «Продлить».", "error");
                return;
            }
            if (sub && normalizeSubscriptionStatus(sub.status) === status) return;
            if (!window.confirm(`Сменить статус подписки на «${label}»?`)) return;
            await runWorkClientAction(async (userId) => {
                const result = await postJson(adminUserSubscriptionUrl(userId), { status });
                renderWorkClientOverview(result?.overview || null);
            }, { successText: `Статус подписки: ${label}`, errorText: "Не удалось сменить статус" });
        });

        async function toggleWorkClientFreeze() {
            const frozen = Boolean(workState.overview?.subscription?.is_frozen);
            if (!window.confirm(`Подтвердить: ${frozen ? "разморозить" : "заморозить"} пользователя?`)) return;
            await runWorkClientAction(async (userId) => {
                const response = await postJson(`${adminUsersUrl}/${userId}/freeze`, { frozen: !frozen });
                const failures = Array.isArray(response?.failures) ? response.failures : [];
                await loadSelectedUserOverview();
                await loadSelectedUserBindings();
                if (failures.length) {
                    throw new Error(`Обновлено не всё: ${failures.length} подключений не изменены.`);
                }
            }, {
                successText: frozen ? "Пользователь разморожен" : "Подписки пользователя заморожены",
                errorText: "Не удалось изменить состояние пользователя",
            });
        }

        workClientRemoveMemberBtnEl?.addEventListener("click", async () => {
            const group = workState.overview?.group;
            if (!group) return;
            if (!window.confirm(`Удалить пользователя из группы «${group.name || group.id}»?`)) return;
            await runWorkClientAction(async (userId) => {
                await deleteJson(`${adminGroupsUrl}/${group.id}/members/${userId}`);
                await loadSelectedUserOverview();
                await loadWorkClientsData();
            }, { successText: "Пользователь удалён из группы", errorText: "Не удалось удалить из группы" });
        });

        workClientManualExtendBtnEl?.addEventListener("click", async () => {
            if (!window.confirm("Продлить подписку пользователя на один месяц?")) return;
            if (!window.confirm("Подтвердите продление ещё раз. Пользователю отправится уведомление.")) return;
            workClientManualExtendBtnEl.disabled = true;
            try {
                await runWorkClientAction(async (userId) => {
                    await postJson(`${adminUsersUrl}/${userId}/manual-extend`, { confirmed: true, months: 1 });
                    await loadSelectedUserOverview();
                }, { successText: "Подписка продлена на месяц", errorText: "Не удалось продлить подписку" });
            } finally {
                workClientManualExtendBtnEl.disabled = false;
            }
        });

        enhanceWorkSelects();

        adminPageButtons.forEach((btn) =>
            btn.addEventListener("click", () => {
                const target = btn.dataset.adminPage || "work-clients-page";
                if (getActiveWorkPageId() === target) return;
                switchWorkPage(target);
                if (target === "work-clients-page") {
                    loadWorkClientsData().catch((err) => {
                        console.error("load clients error:", err);
                    });
                }
            })
        );

        uiSheetCloseEl?.addEventListener("click", () => closeUiSheet(null));
        uiSheetOverlayEl?.addEventListener("click", (event) => {
            if (event.target === uiSheetOverlayEl) closeUiSheet(null);
        });
        uiSheetSearchEl?.addEventListener("input", renderUiSheetItems);

        workUserCreateModeEl?.addEventListener("change", updateUserCreateMode);
        workUserSubscriptionTypeEl?.addEventListener("change", updateUserCreateType);
        workMemberModeEl?.addEventListener("change", updateMemberMode);
        workUserBindingsAddEl?.addEventListener("click", () => {
            addStagedBinding(createDraft.bindings, workUserBindingsListEl, workUserCreateStatusEl);
        });
        workMemberBindingsAddEl?.addEventListener("click", () => {
            addStagedBinding(memberDraft.bindings, workMemberBindingsListEl, workMemberStatusEl);
        });
        workUserMembersAddEl?.addEventListener("click", () => {
            memberPageGroup = null;
            const backBtn = document.querySelector("#work-user-member-page .work-back-btn");
            if (backBtn) backBtn.dataset.workBack = "work-user-create-page";
            workBackTargetByPage.set("work-user-member-page", "work-user-create-page");
            switchWorkPage("work-user-member-page");
        });
        workMemberSaveEl?.addEventListener("click", saveMemberDraft);
        workUserCreateSubmitEl?.addEventListener("click", () => {
            submitUserCreate();
        });

        workVerifyGenerateEl?.addEventListener("click", async () => {
            const baseText = workVerifyGenerateEl?.textContent || "Сгенерировать";
            if (workVerifyGenerateEl) {
                workVerifyGenerateEl.disabled = true;
                workVerifyGenerateEl.textContent = "Генерация...";
            }
            try {
                const count = Number(workVerifyCountEl?.value || 1) || 1;
                const length = Number(workVerifyLengthEl?.value || 5) || 5;
                const payload = await postJson(`${window.location.origin}/api/admin/verification-codes`, {
                    count,
                    length,
                });
                const codes = Array.isArray(payload?.codes) ? payload.codes : [];
                if (workVerifyStatusEl) {
                    workVerifyStatusEl.textContent = codes.length ? `Сгенерировано: ${codes.length}` : "Коды не получены";
                }
                if (workVerifyListEl) {
                    workVerifyListEl.innerHTML = "";
                    if (!codes.length) {
                        const empty = document.createElement("div");
                        empty.className = "work-empty";
                        empty.textContent = "Кодов нет";
                        workVerifyListEl.appendChild(empty);
                    } else {
                        codes.forEach((code) => {
                            const row = document.createElement("div");
                            row.className = "work-link-row";
                            row.textContent = String(code);
                            row.addEventListener("click", async () => {
                                try {
                                    await copyToClipboard(String(code));
                                    row.textContent = `${code} (скопировано)`;
                                    setTimeout(() => {
                                        row.textContent = String(code);
                                    }, 900);
                                } catch (_err) {
                                    row.textContent = `${code} (ошибка)`;
                                    setTimeout(() => {
                                        row.textContent = String(code);
                                    }, 900);
                                }
                            });
                            workVerifyListEl.appendChild(row);
                        });
                    }
                }
            } catch (err) {
                if (workVerifyStatusEl) {
                    workVerifyStatusEl.textContent = err?.message || "Ошибка генерации";
                }
            } finally {
                if (workVerifyGenerateEl) {
                    workVerifyGenerateEl.disabled = false;
                    workVerifyGenerateEl.textContent = baseText;
                }
            }
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

        subscriptionCloudGbEl?.addEventListener("input", () => {
            subscriptionBuilderState.cloudGb = Math.max(0, Number(subscriptionCloudGbEl?.value) || 0);
            scheduleSubscriptionDraft();
        });
        subscriptionDraftBtnEl?.addEventListener("click", async () => {
            await refreshSubscriptionDraft();
        });
        subscriptionConfirmBtnEl?.addEventListener("click", async () => {
            await confirmSubscriptionDraft();
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
                setWorkPanelDetailStatus("Синхронизируем...");
                await syncWorkPanel(panel);
                setWorkPanelDetailStatus("Синхронизация завершена", "success");
            } catch (err) {
                console.error("sync panel error:", err);
                setWorkPanelDetailStatus(err?.message || "Не удалось синхронизировать панель", "error");
            }
        });

        workPanelDetailAccessBtnEl?.addEventListener("click", () => {
            toggleWorkPanelAccessSection(true);
        });
        workPanelAccessCloseEl?.addEventListener("click", () => toggleWorkPanelAccessSection(false));
        workPanelAccessOverlayEl?.addEventListener("click", (event) => {
            if (event.target === workPanelAccessOverlayEl) toggleWorkPanelAccessSection(false);
        });
        workPanelDetailInboundsBtnEl?.addEventListener("click", () => openWorkPanelInbounds());
        workPanelDetailClientsBtnEl?.addEventListener("click", () => {
            openWorkPanelClients().catch((err) => console.error("open panel clients error:", err));
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
            setFormNote(workBindStatusEl, "Обновляем список с серверов…");
            try {
                const result = await refreshInboundClientsFromPanel();
                setFormNote(workBindStatusEl, `Список обновлён. Подключений: ${result.inbounds}`, "success");
            } catch (err) {
                setFormNote(workBindStatusEl, err?.message || "Не удалось обновить список", "error");
            }
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
            fillSelect(workPendingClientSelectEl, [], () => "", () => "", "Select client from inbound");
            if (!workPendingInboundSelectEl?.value) {
                return;
            }
            try {
                await loadPendingInboundClients(workPendingInboundSelectEl.value);
            } catch (err) {
            }
        });

        workPendingTelegramIdEl?.addEventListener("change", async () => {
            try {
                await Promise.all([
                    loadPendingBindings(workPendingTelegramIdEl.value),
                    loadPendingSubscriptionOverview(workPendingTelegramIdEl.value),
                ]);
            } catch (err) {
            }
        });

        workPendingSubStatusSelectEl?.addEventListener("change", () => {
        });

        workPendingSubSaveBtnEl?.addEventListener("click", async () => {
            await runWorkAction("Save Pending Subscription", async () => {
                const telegramId = String(workPendingTelegramIdEl?.value || "").trim();
                if (!isValidTelegramId(telegramId)) {
                    setPendingSubscriptionStatus("Укажи корректный Telegram ID.", "error");
                    throw new Error("Enter valid Telegram ID");
                }

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

        workBindAddBtnEl?.addEventListener("click", async () => {
            const userId = workState.selectedUserId;
            if (!userId) {
                setFormNote(workBindStatusEl, "Сначала открой карточку клиента", "error");
                return;
            }
            setFormNote(workBindStatusEl, "");
            try {
                const picked = await pickServerBinding();
                if (!picked) return;
                await postBinding(userId, picked);
                await loadSelectedUserBindings();
                await loadSelectedUserOverview();
                setFormNote(workBindStatusEl, "Подключение привязано", "success");
            } catch (err) {
                setFormNote(workBindStatusEl, err?.message || "Не удалось привязать подключение", "error");
            }
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

        workClientRoleSaveBtnEl?.addEventListener("click", async () => {
            if (!workState.selectedUserId) {
                setWorkClientRoleStatus("Сначала открой карточку клиента", "error");
                return;
            }
            const nextRole = String(workClientRoleSelectEl?.value || "").trim().toLowerCase();
            if (!nextRole) {
                setWorkClientRoleStatus("Выбери роль", "error");
                return;
            }
            try {
                setWorkClientRoleStatus("Сохраняем роль...");
                const result = await postJson(adminUserRoleUrl(workState.selectedUserId), { role: nextRole });
                const updatedRole = String(result?.user?.role || nextRole).trim().toLowerCase();
                workState.users = workState.users.map((user) =>
                    String(user.id) === String(workState.selectedUserId)
                        ? { ...user, role: updatedRole }
                        : user
                );
                if (workState.overview?.user && String(workState.overview.user.id) === String(workState.selectedUserId)) {
                    workState.overview = {
                        ...workState.overview,
                        user: { ...workState.overview.user, role: updatedRole },
                    };
                }
                if (workClientRoleSelectEl) {
                    workClientRoleSelectEl.value = updatedRole || "user";
                }
                setWorkClientRoleStatus("Роль обновлена", "success");
            } catch (err) {
                console.error("save client role error:", err);
                setWorkClientRoleStatus(err?.message || "Не удалось обновить роль", "error");
            }
        });

        workSubSaveBtnEl?.addEventListener("click", async () => {
            if (!workState.overview?.subscription) {
                setWorkClientActionStatus("Подписки пока нет. Сначала создайте её через «Продлить».", "error");
                return;
            }
            await runWorkClientAction(async (userId) => {
                // День оплаты здесь не трогаем: он задаётся датой в «Продлить».
                const result = await postJson(adminUserSubscriptionUrl(userId), {
                    price_amount: workSubPriceInputEl?.value?.trim() || null,
                    billing_details: workSubBillingDetailsEl?.value?.trim() || null,
                });
                renderWorkClientOverview(result?.overview || null);
            }, { successText: "Цена и реквизиты сохранены", errorText: "Не удалось сохранить" });
        });

        workSubTypeSaveBtnEl?.addEventListener("click", async () => {
            await runWorkClientAction(async (userId) => {
                const payload = { subscription_type: String(workSubscriptionTypeSelectEl?.value || "personal") };
                if (payload.subscription_type === "family_member") {
                    const groupId = Number(workSubGroupSelectEl?.value || 0);
                    if (!groupId) throw new Error("Выбери семью для участника");
                    payload.group_id = groupId;
                }
                const result = await postJson(adminUserSubscriptionUrl(userId), payload);
                renderWorkClientOverview(result?.overview || null);
                await loadWorkClientsData();
            }, { successText: "Тип подписки сохранён", errorText: "Не удалось сохранить тип подписки" });
        });

        // ---- «Изменить идентификацию»: ник, username, Telegram ID и удаление клиента
        function setWorkIdentityStatus(message, tone = "") {
            setFormNote(workClientIdentityStatusEl, message, tone);
        }

        workClientIdentityBtnEl?.addEventListener("click", () => {
            const user = workState.overview?.user || {};
            if (workClientIdentityNameEl) workClientIdentityNameEl.value = user.name || "";
            if (workClientIdentityUsernameEl) workClientIdentityUsernameEl.value = user.username || "";
            if (workClientIdentityTelegramIdEl) workClientIdentityTelegramIdEl.value = user.telegram_id || "";
            setWorkIdentityStatus("");
            setWorkSheetVisible(workClientActionsOverlayEl, false);
            setWorkSheetVisible(workClientIdentityOverlayEl, true);
        });
        workClientIdentityCloseEl?.addEventListener("click", () => setWorkSheetVisible(workClientIdentityOverlayEl, false));

        workClientIdentitySaveEl?.addEventListener("click", async () => {
            const userId = Number(workState.selectedUserId || 0);
            if (!userId) return;
            workClientIdentitySaveEl.disabled = true;
            setWorkIdentityStatus("Сохраняем…");
            try {
                const result = await postJson(`${adminUsersUrl}/${userId}/identity`, {
                    name: workClientIdentityNameEl?.value?.trim() || "",
                    username: workClientIdentityUsernameEl?.value?.trim() || "",
                    telegram_id: workClientIdentityTelegramIdEl?.value?.trim() || "",
                });
                renderWorkClientOverview(result?.overview || null);
                await loadWorkClientsData();
                setWorkIdentityStatus("Сохранено", "success");
            } catch (err) {
                console.error("save identity error:", err);
                setWorkIdentityStatus(err?.message || "Не удалось сохранить", "error");
            } finally {
                workClientIdentitySaveEl.disabled = false;
            }
        });

        workClientIdentityDeleteEl?.addEventListener("click", async () => {
            const userId = Number(workState.selectedUserId || 0);
            if (!userId) return;
            const user = workState.overview?.user || {};
            const label = user.name || (user.username ? `@${user.username}` : `#${userId}`);
            if (!window.confirm(`Удалить клиента «${label}» полностью? Это нельзя отменить.`)) return;
            if (!window.confirm("Точно удалить? Подписки и платежи клиента тоже будут стёрты.")) return;
            workClientIdentityDeleteEl.disabled = true;
            try {
                await deleteJson(`${adminUsersUrl}/${userId}`);
                closeWorkSheets();
                workState.selectedUserId = null;
                switchWorkPage("work-clients-page");
                await loadWorkClientsData();
            } catch (err) {
                console.error("delete user error:", err);
                setWorkIdentityStatus(err?.message || "Не удалось удалить клиента", "error");
            } finally {
                workClientIdentityDeleteEl.disabled = false;
            }
        });

        workSubTypeChipsEl?.addEventListener("click", (event) => {
            const btn = event.target.closest("[data-sub-type]");
            if (!btn || !workSubscriptionTypeSelectEl) return;
            workSubscriptionTypeSelectEl.value = btn.dataset.subType;
            workSubscriptionTypeSelectEl.dispatchEvent(new Event("change", { bubbles: true }));
            workSubTypeChipsEl.querySelectorAll("[data-sub-type]").forEach((chip) => {
                chip.classList.toggle("active", chip === btn);
            });
        });

        function setWorkSubNotesStatus(message, tone = "") {
            if (!workSubNotesStatusEl) return;
            workSubNotesStatusEl.classList.remove("success", "error");
            if (!message) {
                workSubNotesStatusEl.textContent = "";
                workSubNotesStatusEl.classList.add("hidden");
                return;
            }
            if (tone === "success" || tone === "error") workSubNotesStatusEl.classList.add(tone);
            workSubNotesStatusEl.textContent = message;
            workSubNotesStatusEl.classList.remove("hidden");
        }

        workSubNotesSaveBtnEl?.addEventListener("click", async () => {
            const userId = Number(workState.selectedUserId || 0);
            if (!userId) return;
            if (!workState.overview?.subscription) {
                setWorkSubNotesStatus("Подписки пока нет. Сначала создайте её через «Продлить».", "error");
                return;
            }
            workSubNotesSaveBtnEl.disabled = true;
            try {
                const result = await postJson(adminUserSubscriptionUrl(userId), {
                    notes: workSubNotesEl?.value?.trim() || null,
                });
                renderWorkClientOverview(result?.overview || null);
                setWorkSubNotesStatus("Сохранено", "success");
            } catch (err) {
                console.error("save notes error:", err);
                setWorkSubNotesStatus(err?.message || "Не удалось сохранить", "error");
            } finally {
                workSubNotesSaveBtnEl.disabled = false;
            }
        });

        workSubExtendBtnEl?.addEventListener("click", async () => {
            const months = Number(workSubExtendRangeEl?.value || 0);
            if (!Number.isInteger(months) || months <= 0) {
                setWorkClientActionStatus("Выбери срок продления", "error");
                return;
            }
            await runWorkClientAction(async (userId) => {
                const result = await postJson(adminUserSubscriptionUrl(userId), { extend_months: months });
                renderWorkClientOverview(result?.overview || null);
            }, { successText: `Продлено: ${fmtMonthsText(months)}`, errorText: "Не удалось продлить подписку" });
        });

        workSubDateBtnEl?.addEventListener("click", async () => {
            await runWorkClientAction(async (userId) => {
                const accessUntil = validateSubscriptionDateValue(workSubCreateDateEl?.value);
                const payload = { status: "active", access_until: accessUntil };
                if (!isWorkClientGroupMember(workState.overview)) {
                    // Выбранная вручную дата окончания определяет и день оплаты.
                    const billingDay = Number(String(accessUntil).slice(8, 10));
                    if (billingDay >= 1 && billingDay <= 31) payload.billing_day = billingDay;
                }
                const result = await postJson(adminUserSubscriptionUrl(userId), payload);
                renderWorkClientOverview(result?.overview || null);
            }, { successText: "Дата окончания подписки обновлена", errorText: "Не удалось установить дату" });
        });

        workSubExtendRangeEl?.addEventListener("input", () => {
            renderWorkSubExtendValue();
        });
        workSubscriptionTypeSelectEl?.addEventListener("change", () => {
            workSubGroupWrapEl?.classList.toggle(
                "hidden",
                workSubscriptionTypeSelectEl.value !== "family_member"
            );
        });
        renderWorkSubExtendValue();
        updateCloudPageContext(cloudState.path);
        updateCloudUpButton();
