import "pe"

rule SIGNATURE_BASE_HKTL_NET_GUID_Httpsbeaconshell : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d66e3566-6082-570a-a168-f44c9d8c7619"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_github_net_redteam_tools_guids.yar#L622-L636"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b0c40d1ab0bfc34a0f27e7e3f84522a93c0d635cba929a708fbd38dfce4404fb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "aca853dc-9e74-4175-8170-e85372d5f2a9" ascii wide
		$typelibguid0up = "ACA853DC-9E74-4175-8170-E85372D5F2A9" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
