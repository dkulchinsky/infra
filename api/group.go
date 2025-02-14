package api

import (
	"github.com/infrahq/infra/uid"
)

type Group struct {
	ID      uid.ID `json:"id"`
	Name    string `json:"name"`
	Created Time   `json:"created"`
	Updated Time   `json:"updated"`
}

type ListGroupsRequest struct {
	// Name filters the results to only the group matching this name.
	Name string `form:"name"`
	// UserID filters the results to only groups where this user is a member.
	UserID uid.ID `form:"userID"`
	PaginationRequest
}

type CreateGroupRequest struct {
	Name string `json:"name" validate:"required"`
}

type UpdateUsersInGroupRequest struct {
	GroupID         uid.ID   `uri:"id" json:"-" validate:"required"`
	UserIDsToAdd    []uid.ID `json:"usersToAdd"`
	UserIDsToRemove []uid.ID `json:"usersToRemove"`
}
