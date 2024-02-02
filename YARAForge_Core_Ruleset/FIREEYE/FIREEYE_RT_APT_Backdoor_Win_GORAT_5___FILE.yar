rule FIREEYE_RT_APT_Backdoor_Win_GORAT_5___FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "73102bd2-7b94-5c7b-b9a4-cfc9cf5e3212"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/REDFLARE (Gorat)/production/yara/APT_Backdoor_Win_GORAT_5.yar#L4-L23"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "cdf58a48757010d9891c62940c439adb, a107850eb20a4bb3cc59dbd6861eaf0f"
		logic_hash = "67f85fb3bedfd18a1226c92318f387be3c7ff9566ca2d554c49cf62389482552"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$1 = "comms.BeaconData" fullword
		$2 = "comms.CommandResponse" fullword
		$3 = "rat.BaseChannel" fullword
		$4 = "rat.Config" fullword
		$5 = "rat.Core" fullword
		$6 = "platforms.AgentPlatform" fullword
		$7 = "GetHostID" fullword
		$8 = "/rat/cmd/gorat_shared/dllmain.go" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}