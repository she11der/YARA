import "pe"

rule SIGNATURE_BASE_APT_Backdoor_Win_Gorat_Memory_1
{
	meta:
		description = "Identifies GoRat malware in memory based on strings."
		author = "FireEye"
		id = "4fcdd98f-1873-58e1-a9f5-73ee0aa5a69f"
		date = "2023-12-12"
		modified = "2023-12-12"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_fireeye_redteam_tools.yar#L1013-L1039"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3b926b5762e13ceec7ac3a61e85c93bb"
		logic_hash = "bf8d80b7a7d35c1bcb353ff66d10bc95c2e6502043acc6554887465a467cdcf7"
		score = 75
		quality = 85
		tags = ""

	strings:
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
		$winblows or 3 of ($rat*)
}
