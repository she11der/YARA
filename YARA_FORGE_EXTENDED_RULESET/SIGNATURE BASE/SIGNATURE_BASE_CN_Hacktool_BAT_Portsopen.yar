import "pe"

rule SIGNATURE_BASE_CN_Hacktool_BAT_Portsopen
{
	meta:
		description = "Detects a chinese BAT hacktool for local port evaluation"
		author = "Florian Roth (Nextron Systems)"
		id = "55c3f678-ba70-5a4a-b288-9d0953eff968"
		date = "2014-12-10"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L604-L618"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e5bc7b3264d7fc63fcc6c3d7e45859eb83b8ce60bd9a918f5eff887f626d09a3"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "for /f \"skip=4 tokens=2,5\" %%a in ('netstat -ano -p TCP') do (" ascii
		$s1 = "in ('tasklist /fi \"PID eq %%b\" /FO CSV') do " ascii
		$s2 = "@echo off" ascii

	condition:
		all of them
}
