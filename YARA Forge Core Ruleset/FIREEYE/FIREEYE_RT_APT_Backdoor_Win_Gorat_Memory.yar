rule FIREEYE_RT_APT_Backdoor_Win_Gorat_Memory
{
	meta:
		description = "Identifies GoRat malware in memory based on strings."
		author = "FireEye"
		id = "16fb1db7-711c-5d8d-9203-738c94f253fe"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/REDFLARE (Gorat)/production/yara/APT_Backdoor_Win_GoRat_Memory.yar#L4-L27"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "3b926b5762e13ceec7ac3a61e85c93bb"
		logic_hash = "88272e59325d106f96d6b6f1d57daf968823c1e760067dee0334c66c521ce8c2"
		score = 75
		quality = 75
		tags = ""
		rev = 1

	strings:
		$murica = "murica" fullword
		$rat1 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
		$rat2 = "rat.(*Core).generateBeacon" fullword
		$rat3 = "rat.gJitter" fullword
		$rat4 = "rat/comms.(*protectedChannel).SendCmdResponse" fullword
		$rat5 = "rat/modules/filemgmt.(*acquire).NewCommandExecution" fullword
		$rat6 = "rat/modules/latlisten.(*latlistensrv).handleCmd" fullword
		$rat7 = "rat/modules/netsweeper.(*netsweeperRunner).runSweep" fullword
		$rat8 = "rat/modules/netsweeper.(*Pinger).listen" fullword
		$rat9 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
		$rat10 = "rat/platforms/win/dyloader.(*memoryLoader).ExecutePluginFunction" fullword
		$rat11 = "rat/platforms/win/modules/namedpipe.(*dummy).Open" fullword
		$winblows = "rat/platforms/win.(*winblows).GetStage" fullword

	condition:
		$winblows or #murica>10 or 3 of ($rat*)
}