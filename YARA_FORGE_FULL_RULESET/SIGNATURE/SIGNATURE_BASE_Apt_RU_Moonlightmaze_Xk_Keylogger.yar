rule SIGNATURE_BASE_Apt_RU_Moonlightmaze_Xk_Keylogger
{
	meta:
		description = "Rule to detect Moonlight Maze 'xk' keylogger"
		author = "Kaspersky Lab"
		id = "cf585cd0-afdd-5782-a6e5-bb9509cbf01d"
		date = "2017-03-27"
		modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_moonlightmaze.yar#L170-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b2acdef9c8e545f4ab217f529a7e4a3e74723b27ec89896f98639fd40792bcc8"
		score = 75
		quality = 35
		tags = ""
		version = "1.0"

	strings:
		$a1 = "Log ended at => %s"
		$a2 = "Log started at => %s [pid %d]"
		$a3 = "/var/tmp/task" fullword
		$a4 = "/var/tmp/taskhost" fullword
		$a5 = "my hostname: %s"
		$a6 = "/var/tmp/tasklog"
		$a7 = "/var/tmp/.Xtmp01" fullword
		$a8 = "myfilename=-%s-"
		$a9 = "/var/tmp/taskpid"
		$a10 = "mypid=-%d-" fullword
		$a11 = "/var/tmp/taskgid" fullword
		$a12 = "mygid=-%d-" fullword

	condition:
		((3 of ($a*)))
}
