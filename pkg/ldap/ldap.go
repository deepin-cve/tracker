package ldap

import (
	"crypto/tls"
	"fmt"
	"time"

	ldapBase "gopkg.in/ldap.v3"
)

// Client ldap wrapper
type Client struct {
	conn       *ldapBase.Conn
	dn         string
	password   string
	userSearch string
}

// NewClient New LDAP client
func NewClient(host string, port int, dn, password, userSearch string) (client *Client, err error) {
	var conn *ldapBase.Conn
	ldapBase.DefaultTimeout = 20 * time.Second
	conn, err = ldapBase.DialTLS("tcp", host+":"+fmt.Sprint(port),
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	client = &Client{
		conn:       conn,
		dn:         dn,
		password:   password,
		userSearch: userSearch,
	}
	return
}

func (c *Client) prepare() (err error) {
	err = c.conn.Bind(c.dn, c.password)
	if err != nil {
		err = fmt.Errorf("LDAP dn is not set properly: %s", err)
	}
	return
}

// CheckUserPassword auth user
func (c *Client) CheckUserPassword(username, password string) (err error) {
	err = c.prepare()
	if err != nil {
		return
	}
	req := ldapBase.NewSearchRequest(
		c.userSearch, ldapBase.ScopeWholeSubtree, ldapBase.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(uid=%s)", ldapBase.EscapeFilter(username)),
		[]string{"dn"}, nil)
	resp, err := c.conn.Search(req)
	if err != nil {
		return
	}
	if len(resp.Entries) != 1 {
		err = fmt.Errorf("ldap failed to match")
		return
	}
	userDn := resp.Entries[0].DN
	err = c.conn.Bind(userDn, password)
	if err != nil {
		err = fmt.Errorf("invalid username or password")
		return
	}
	return
}

// Close close ldap connection
func (c *Client) Close() {
	c.conn.Close()
}
