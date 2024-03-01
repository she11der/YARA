import "pe"

rule SIGNATURE_BASE_CN_Hacktool_Milkt_BAT
{
	meta:
		description = "Detects a chinese Portscanner named MilkT - shipped BAT"
		author = "Florian Roth (Nextron Systems)"
		id = "d680a5f1-6182-5bc8-99de-c3cba1a61903"
		date = "2014-12-10"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L668-L681"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ad74c45db0ef52223eb4dd162a21c57074a4ecb869a841d836d14afc997a7478"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" ascii
		$s1 = "if not \"%Choice%\"==\"\" set Choice=%Choice:~0,1%" ascii

	condition:
		all of them
}
