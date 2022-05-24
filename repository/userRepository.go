package repository

//Not full
func getAll() {
	DB.Prepare("SELECT * FROM users")
}