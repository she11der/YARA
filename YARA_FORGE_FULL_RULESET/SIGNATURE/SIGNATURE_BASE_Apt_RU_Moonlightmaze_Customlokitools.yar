rule SIGNATURE_BASE_Apt_RU_Moonlightmaze_Customlokitools : FILE
{
	meta:
		description = "Rule to detect Moonlight Maze Loki samples by custom attacker-authored strings"
		author = "Kaspersky Lab"
		id = "d5795d3b-bbb1-59e9-b86d-666b5c911f3b"
		date = "2017-03-15"
		modified = "2017-03-22"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_moonlightmaze.yar#L11-L47"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "14cce7e641d308c3a177a8abb5457019"
		hash = "a3164d2bbc45fb1eef5fde7eb8b245ea"
		hash = "dabee9a7ea0ddaf900ef1e3e166ffe8a"
		hash = "1980958afffb6a9d5a6c73fc1e2795c2"
		hash = "e59f92aadb6505f29a9f368ab803082e"
		logic_hash = "4e1f60b045c10758354f110c3778b8ffd7f10b5e229b3f2f821287476620bec9"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.1"

	strings:
		$a1 = "Write file Ok..." ascii wide
		$a2 = "ERROR: Can not open socket...." ascii wide
		$a3 = "Error in parametrs:" ascii wide
		$a4 = "Usage: @<get/put> <IP> <PORT> <file>" ascii wide
		$a5 = "ERROR: Not connect..." ascii wide
		$a6 = "Connect successful...." ascii wide
		$a7 = "clnt <%d> rqstd n ll kll" ascii wide
		$a8 = "clnt <%d> rqstd swap" ascii wide
		$a9 = "cld nt sgnl prcs grp" ascii wide
		$a10 = "cld nt sgnl prnt" ascii wide
		$a11 = "ork error" ascii fullword

	condition:
		filesize <5000KB and 3 of ($a*)
}
