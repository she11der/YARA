import "pe"

rule SIGNATURE_BASE_CN_Toolset_Sig_1433_135_Sqlr
{
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "74038975-ef06-53d6-bdcc-02706408b596"
		date = "2015-03-30"
		modified = "2023-12-05"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3030-L3047"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8542c7fb8291b02db54d2dc58cd608e612bfdc57"
		logic_hash = "14c9d104cfb71a2d3545bfb6274e3a282d4597f38057187d76adaf26fe2718fa"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Connect to %s MSSQL server success. Type Command at Prompt." fullword ascii
		$s11 = ";DATABASE=master" fullword ascii
		$s12 = "xp_cmdshell '" fullword ascii
		$s14 = "SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=myserver" ascii

	condition:
		all of them
}
