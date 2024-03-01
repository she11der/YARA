import "pe"

rule ARKBIRD_SOLG_APT_APT28_Zebrocy_GO_Downloader_Nov_2020_1 : FILE
{
	meta:
		description = "Detect Zebrocy Go downloader (November 2020)"
		author = "Arkbird_SOLG"
		id = "114c0297-7168-5d20-b56b-89b0b47f18c7"
		date = "2020-12-09"
		modified = "2020-12-10"
		reference = "https://www.intezer.com/blog/research/russian-apt-uses-covid-19-lures-to-deliver-zebrocy/"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-12-09/APT28/APT_APT28_Nov_2020_1.yar#L37-L65"
		license_url = "N/A"
		logic_hash = "e7b2e7c250f3a98127399176adf9f93b758f0a5111e126dd0a75a3fb95a48da9"
		score = 50
		quality = 61
		tags = "FILE"
		level = "experimental"
		hash1 = "61c2e524dcc25a59d7f2fe7eff269865a3ed14d6b40e4fea33b3cd3f58c14f19"
		hash2 = "f36a0ee7f4ec23765bb28fbfa734e402042278864e246a54b8c4db6f58275662"

	strings:
		$c1 = "os.(*ProcessState).sys" fullword ascii
		$c2 = "os/exec.(*ExitError).Sys" fullword ascii
		$c3 = "os/exec.ExitError.Sys" fullword ascii
		$c4 = "os.(*ProcessState).Sys" fullword ascii
		$p1 = "syscall.CreatePipe" fullword ascii
		$p2 = "os.Pipe" fullword ascii
		$p3 = { 6e 65 74 2f 68 74 74 70 2e 28 2a 68 74 74 70 32 70 69 70 65 29 2e 63 6c 6f 73 65 44 6f 6e 65 4c 6f 63 6b 65 64 }
		$p4 = { 6e 65 74 2f 68 74 74 70 2e 28 2a 68 74 74 70 32 63 6c 69 65 6e 74 53 74 72 65 61 6d 29 2e 67 65 74 53 74 61 72 74 65 64 57 72 69 74 65 }
		$op1 = { 75 5f 67 3d 25 73 20 25 71 25 73 2a 25 64 25 73 3d 25 73 26 23 33 34 3b 26 23 33 39 3b 26 61 6d 70 3b }
		$op2 = { 70 63 3d 25 21 28 4e 4f 56 45 52 42 29 25 21 57 65 65 6b 64 61 79 28 25 73 7c 25 73 25 73 7c 25 73 28 42 41 44 49 4e 44 45 58 29 }
		$op3 = { 48 54 54 50 5f 50 52 4f 58 59 48 6f 73 74 3a 20 25 73 0d 0a 49 50 20 61 64 64 72 65 73 73 4b 65 65 70 2d 41 6c 69 76 65 }
		$op4 = { 63 6f 6e 6e 65 63 74 69 6f 6e 20 65 72 72 6f 72 3a 20 25 73 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 69 6d 65 64 20 6f 75 74 }
		$op5 = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 54 45 53 54 49 4e 47 20 4b 45 59 2d 2d 2d 2d 2d }
		$op6 = { 2d 2d 2d 2d 2d 45 4e 44 20 52 53 41 20 54 45 53 54 49 4e 47 20 4b 45 59 2d 2d 2d 2d 2d }

	condition:
		uint16(0)==0x4d5a and filesize >800KB and (pe.imphash()=="91802a615b3a5c4bcc05bc5f66a5b219") and 3 of ($c*) and 3 of ($p*) and 3 of ($op*)
}
