// Package vaultwarden holds the Vaultwarden enums the exporter turns into
// readable names (event types, device types, two-factor methods, statuses).
// Values come from the Vaultwarden sources (src/db/models), which mirror the
// upstream Bitwarden server enums.
package vaultwarden

import "strconv"

// EventTypes maps EventType (src/db/models/event.rs) to its name
var EventTypes = map[int]string{
	1000: "UserLoggedIn",
	1001: "UserChangedPassword",
	1002: "UserUpdated2fa",
	1003: "UserDisabled2fa",
	1004: "UserRecovered2fa",
	1005: "UserFailedLogIn",
	1006: "UserFailedLogIn2fa",
	1007: "UserClientExportedVault",
	1010: "UserRequestedDeviceApproval",
	1100: "CipherCreated",
	1101: "CipherUpdated",
	1102: "CipherDeleted",
	1103: "CipherAttachmentCreated",
	1104: "CipherAttachmentDeleted",
	1105: "CipherShared",
	1106: "CipherUpdatedCollections",
	1107: "CipherClientViewed",
	1108: "CipherClientToggledPasswordVisible",
	1109: "CipherClientToggledHiddenFieldVisible",
	1110: "CipherClientToggledCardCodeVisible",
	1111: "CipherClientCopiedPassword",
	1112: "CipherClientCopiedHiddenField",
	1113: "CipherClientCopiedCardCode",
	1114: "CipherClientAutofilled",
	1115: "CipherSoftDeleted",
	1116: "CipherRestored",
	1117: "CipherClientToggledCardNumberVisible",
	1133: "CipherClientHttpAuthReleased",
	1300: "CollectionCreated",
	1301: "CollectionUpdated",
	1302: "CollectionDeleted",
	1400: "GroupCreated",
	1401: "GroupUpdated",
	1402: "GroupDeleted",
	1500: "OrganizationUserInvited",
	1501: "OrganizationUserConfirmed",
	1502: "OrganizationUserUpdated",
	1503: "OrganizationUserRemoved",
	1504: "OrganizationUserUpdatedGroups",
	1505: "OrganizationUserUnlinkedSso",
	1506: "OrganizationUserResetPasswordEnroll",
	1507: "OrganizationUserResetPasswordWithdraw",
	1508: "OrganizationUserAdminResetPassword",
	1511: "OrganizationUserRevoked",
	1512: "OrganizationUserRestored",
	1513: "OrganizationUserApprovedAuthRequest",
	1514: "OrganizationUserRejectedAuthRequest",
	1515: "OrganizationUserDeleted",
	1516: "OrganizationUserLeft",
	1519: "OrganizationUserAdminResetTwoFactor",
	1520: "OrganizationUserRevokedTwoFactorNonCompliance",
	1521: "OrganizationUserRevokedSingleOrganizationNonCompliance",
	1522: "OrganizationUserNotificationBannerActionClicked",
	1600: "OrganizationUpdated",
	1601: "OrganizationPurgedVault",
	1602: "OrganizationClientExportedVault",
	1700: "PolicyUpdated",
}

// DeviceTypes maps DeviceType (src/db/models/device.rs) to its name
var DeviceTypes = map[int]string{
	0:  "Android",
	1:  "Ios",
	2:  "ChromeExtension",
	3:  "FirefoxExtension",
	4:  "OperaExtension",
	5:  "EdgeExtension",
	6:  "WindowsDesktop",
	7:  "MacOsDesktop",
	8:  "LinuxDesktop",
	9:  "ChromeBrowser",
	10: "FirefoxBrowser",
	11: "OperaBrowser",
	12: "EdgeBrowser",
	13: "IEBrowser",
	14: "UnknownBrowser",
	15: "AndroidAmazon",
	16: "Uwp",
	17: "SafariBrowser",
	18: "VivaldiBrowser",
	19: "VivaldiExtension",
	20: "SafariExtension",
	21: "Sdk",
	22: "Server",
	23: "WindowsCLI",
	24: "MacOsCLI",
	25: "LinuxCLI",
	26: "DuckDuckGoBrowser",
}

// TwoFactorTypes maps the two-factor methods a user can enable
// (src/db/models/two_factor.rs). Remember (5), recovery codes and the
// challenge types (1000+) are not methods and are left out.
var TwoFactorTypes = map[int]string{
	0: "authenticator",
	1: "email",
	2: "duo",
	3: "yubikey",
	4: "u2f",
	6: "organization_duo",
	7: "webauthn",
}

// MembershipStatuses maps MembershipStatus (src/db/models/organization.rs)
var MembershipStatuses = map[int]string{
	-1: "revoked",
	0:  "invited",
	1:  "accepted",
	2:  "confirmed",
}

// MembershipTypes maps MembershipType (src/db/models/organization.rs)
var MembershipTypes = map[int]string{
	0: "owner",
	1: "admin",
	2: "user",
	3: "manager",
}

// CipherTypes maps the cipher (vault item) types (src/api/core/ciphers.rs)
var CipherTypes = map[int]string{
	1: "login",
	2: "secure_note",
	3: "card",
	4: "identity",
	5: "ssh_key",
}

// SendTypes maps SendType (src/db/models/send.rs)
var SendTypes = map[int]string{
	0: "text",
	1: "file",
}

// EmergencyAccessStatuses maps EmergencyAccessStatus (src/db/models/emergency_access.rs)
var EmergencyAccessStatuses = map[int]string{
	0: "invited",
	1: "accepted",
	2: "confirmed",
	3: "recovery_initiated",
	4: "recovery_approved",
}

// Name returns the name of a code in an enum, or "unknown_<code>"
func Name(enum map[int]string, code int) string {
	if name, ok := enum[code]; ok {
		return name
	}
	return "unknown_" + strconv.Itoa(code)
}

// EventCode returns the code of an event name, and whether it exists
func EventCode(name string) (int, bool) {
	for code, n := range EventTypes {
		if n == name {
			return code, true
		}
	}
	return 0, false
}
