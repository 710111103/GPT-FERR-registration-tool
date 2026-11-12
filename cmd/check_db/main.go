package main

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "turb.sqlite3")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, email, length(access_token), status, live_check_status, created_at FROM accounts ORDER BY id DESC LIMIT 30")
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	fmt.Printf("%-5s %-32s %-8s %-12s %-12s %s\n", "ID", "Email", "AT_Len", "Status", "Live", "Created")
	for rows.Next() {
		var id int
		var email, status string
		var atLen sql.NullInt64
		var live sql.NullString
		var created string
		if err := rows.Scan(&id, &email, &atLen, &status, &live, &created); err != nil {
			panic(err)
		}
		fmt.Printf("%-5d %-32s %-8d %-12s %-12s %s\n", id, email, atLen.Int64, status, live.String, created)
	}
}
