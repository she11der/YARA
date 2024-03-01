rule SIGNATURE_BASE_Win_Privesc_Adaclscan4_3
{
	meta:
		description = "Detects a tool that can be used for privilege escalation - file ADACLScan4.3.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "15867a9c-9b9b-5d29-bf51-2b3e91af556f"
		date = "2016-06-02"
		modified = "2023-12-05"
		reference = "https://adaclscan.codeplex.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_win_privesc.yar#L46-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ca657e5c4172d240f46a890fc112ee89d5bdf9e35e7d412332ee11bdaf166215"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3473ddb452de7640fab03cad3e8aaf6a527bdd6a7a311909cfef9de0b4b78333"

	strings:
		$s1 = "<Label x:Name=\"lblPort\" Content=\"Port:\"  HorizontalAlignment=\"Left\" Height=\"28\" Margin=\"10,0,0,0\" Width=\"35\"/>" fullword ascii
		$s2 = "(([System.IconExtractor]::Extract(\"mmcndmgr.dll\", 126, $true)).ToBitMap()).Save($env:temp + \"\\Other.png\")    " fullword ascii
		$s3 = "$bolValid = $ctx.ValidateCredentials($psCred.UserName,$psCred.GetNetworkCredential().Password)" fullword ascii

	condition:
		all of them
}
