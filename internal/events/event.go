// Package events streams the Vaultwarden audit events (table "event") as JSON
// lines: logins and failed logins, two-factor, vault items viewed / copied /
// exported, organization membership, groups, collections, policies...
package events

import (
	"database/sql"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/database"
	"github.com/maximewewer/vaultwarden-exporter/internal/vaultwarden"
)

// Event is one exported audit event. Empty fields are omitted.
type Event struct {
	Source       string            `json:"source"`
	Kind         string            `json:"kind"`
	Timestamp    string            `json:"timestamp"`
	EventID      string            `json:"event_id"`
	EventType    int               `json:"event_type"`
	EventName    string            `json:"event_name"`
	OrgID        string            `json:"org_id,omitempty"`
	OrgName      string            `json:"org_name,omitempty"`
	UserID       string            `json:"user_id,omitempty"`
	UserEmail    string            `json:"user_email,omitempty"`
	ActorID      string            `json:"actor_id,omitempty"`
	ActorEmail   string            `json:"actor_email,omitempty"`
	ActorName    string            `json:"actor_name,omitempty"`
	MemberID     string            `json:"member_id,omitempty"`
	MemberEmail  string            `json:"member_email,omitempty"`
	MemberName   string            `json:"member_name,omitempty"`
	CipherID     string            `json:"cipher_id,omitempty"`
	CollectionID string            `json:"collection_id,omitempty"`
	GroupID      string            `json:"group_id,omitempty"`
	PolicyID     string            `json:"policy_id,omitempty"`
	DeviceType   *int              `json:"device_type,omitempty"`
	DeviceName   string            `json:"device_name,omitempty"`
	IP           string            `json:"ip,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`

	date time.Time
}

// columns are the selected columns, in scan order
const columns = `e.uuid, e.event_type, e.event_date, e.org_uuid, e.user_uuid, e.act_user_uuid, e.org_user_uuid,
  e.cipher_uuid, e.collection_uuid, e.group_uuid, e.policy_uuid, e.device_type, e.ip_address,
  o.name, u.email, a.email, a.name, mu.email, mu.name`

// fromClause joins the readable names. The exporter role only needs
// users(uuid, email, name), organizations(uuid, name) and
// users_organizations(uuid, user_uuid) besides the event table. The member
// join names the user an organization event is about (invited, confirmed,
// removed, role changed...): org_user_uuid is a membership, not a user. Once a
// membership is deleted, its member fields are empty.
const fromClause = `FROM event e
LEFT JOIN organizations o ON o.uuid = e.org_uuid
LEFT JOIN users u ON u.uuid = e.user_uuid
LEFT JOIN users a ON a.uuid = e.act_user_uuid
LEFT JOIN users_organizations m ON m.uuid = e.org_user_uuid
LEFT JOIN users mu ON mu.uuid = m.user_uuid`

// scanEvent reads a row selected with columns
func scanEvent(scan func(...any) error) (*Event, error) {
	var (
		id, ip, orgName, userEmail, actorEmail, actorName, memberEmail, memberName sql.NullString
		org, user, actor, member, cipher, collection, group, policy                sql.NullString
		eventType                                                                  int64
		device                                                                     sql.NullInt64
		rawDate                                                                    any
	)
	if err := scan(&id, &eventType, &rawDate, &org, &user, &actor, &member, &cipher, &collection, &group,
		&policy, &device, &ip, &orgName, &userEmail, &actorEmail, &actorName, &memberEmail, &memberName); err != nil {
		return nil, err
	}
	date, err := database.ParseTime(rawDate)
	if err != nil {
		return nil, err
	}
	e := &Event{
		Source: "vaultwarden", Kind: "audit_event",
		Timestamp: date.Format("2006-01-02T15:04:05.000000Z"),
		EventID:   trim(id), EventType: int(eventType),
		EventName: vaultwarden.Name(vaultwarden.EventTypes, int(eventType)),
		OrgID:     trim(org), OrgName: orgName.String,
		UserID: trim(user), UserEmail: userEmail.String,
		ActorID: trim(actor), ActorEmail: actorEmail.String, ActorName: actorName.String,
		MemberID: trim(member), MemberEmail: memberEmail.String, MemberName: memberName.String, CipherID: trim(cipher), CollectionID: trim(collection),
		GroupID: trim(group), PolicyID: trim(policy), IP: ip.String,
		date: date,
	}
	if device.Valid {
		d := int(device.Int64)
		e.DeviceType = &d
		e.DeviceName = vaultwarden.Name(vaultwarden.DeviceTypes, d)
	}
	return e, nil
}

// trim drops the padding of CHAR(36) columns
func trim(s sql.NullString) string {
	if !s.Valid {
		return ""
	}
	b := []byte(s.String)
	for len(b) > 0 && b[len(b)-1] == ' ' {
		b = b[:len(b)-1]
	}
	return string(b)
}

// isUserEvent reports whether an event type is a user event (1000-1099),
// stored once without organization and once per organization of the user
func isUserEvent(eventType int) bool {
	return eventType >= 1000 && eventType < 1100
}
