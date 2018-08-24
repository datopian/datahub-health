from health import check

db_health = check.HealtCheck(user_info='config.json')

db_health.check_health()
db_health.display_report()
assert db_health.alles_good()
