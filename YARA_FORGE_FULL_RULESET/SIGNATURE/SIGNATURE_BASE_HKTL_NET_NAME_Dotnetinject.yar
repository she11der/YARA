rule SIGNATURE_BASE_HKTL_NET_NAME_Dotnetinject : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "468f89c4-5b94-53be-b9e6-ad21de7d98ba"
		date = "2021-01-22"
		modified = "2022-06-28"
		reference = "https://github.com/dtrizna/DotNetInject"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_github_net_redteam_tools_names.yar#L182-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "07ba4ba23372dbc2618dcea89ef643cd68371ace1116bfeb939b0f9adfc425bb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "DotNetInject" ascii wide
		$compile = "AssemblyTitle" ascii wide
		$fp1 = "GetDotNetInjector" ascii
		$fp2 = "JetBrains.TeamCity.Injector." wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and filesize <20MB and $name and $compile and not 1 of ($fp*)
}