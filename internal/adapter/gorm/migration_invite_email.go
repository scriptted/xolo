package gorm

import (
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

const inviteEmailMigrationID = "202610070002"

// migrateNormalizeInviteeEmails brings the invitations written before
// model.NormalizeEmail to the form every reader now expects: trimmed,
// lowercased, and NULL for a blank address, which names nobody.
func migrateNormalizeInviteeEmails(tx *gorm.DB) error {
	if !tx.Migrator().HasTable(&InviteToken{}) {
		return nil
	}
	return errors.WithStack(tx.Exec("UPDATE invite_tokens SET invitee_email = NULLIF(LOWER(TRIM(invitee_email)), '') WHERE invitee_email IS NOT NULL").Error)
}
