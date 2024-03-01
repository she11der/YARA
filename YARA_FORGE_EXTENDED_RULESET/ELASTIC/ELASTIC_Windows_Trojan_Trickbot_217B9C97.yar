rule ELASTIC_Windows_Trojan_Trickbot_217B9C97 : FILE MEMORY
{
	meta:
		description = "Targets pwgrab64.dll module containing functionality use to retrieve local passwords"
		author = "Elastic Security"
		id = "217b9c97-a637-49b8-a652-5a42ea19ee8e"
		date = "2021-03-29"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Trojan_Trickbot.yar#L566-L601"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "1e90a73793017720c9a020069ed1c87879174c19c3b619e5b78db8220a63e9b7"
		logic_hash = "9b2b8a8154d4aba06029fd35d896331449f7baa961f183fb0cb47e890610ff99"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "7d5dcb60526a80926bbaa7e3cd9958719e326a160455095ff9f0315e85b8adf6"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "pwgrab.dll" ascii fullword
		$a2 = "\\\\.\\pipe\\pidplacesomepipe" ascii fullword
		$a3 = "\\Google\\Chrome\\User Data\\Default\\Login Data.bak" ascii fullword
		$a4 = "select origin_url, username_value, password_value, length(password_value) from logins where blacklisted_by_user = 0" ascii fullword
		$a5 = "<moduleconfig><autostart>yes</autostart><all>yes</all><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"dpost"
		$a6 = "Grab_Passwords_Chrome(0)" ascii fullword
		$a7 = "Grab_Passwords_Chrome(1)" ascii fullword
		$a8 = "=\"dpost\" period=\"60\"/></autoconf></moduleconfig>" ascii fullword
		$a9 = "Grab_Passwords_Chrome(): Can't open database" ascii fullword
		$a10 = "UPDATE %Q.%s SET sql = CASE WHEN type = 'trigger' THEN sqlite_rename_trigger(sql, %Q)ELSE sqlite_rename_table(sql, %Q) END, tbl_"
		$a11 = "Chrome login db copied" ascii fullword
		$a12 = "Skip Chrome login db copy" ascii fullword
		$a13 = "Mozilla\\Firefox\\Profiles\\" ascii fullword
		$a14 = "Grab_Passwords_Chrome() success" ascii fullword
		$a15 = "No password provided by user" ascii fullword
		$a16 = "Chrome login db should be copied (copy absent)" ascii fullword
		$a17 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" wide fullword

	condition:
		4 of ($a*)
}
