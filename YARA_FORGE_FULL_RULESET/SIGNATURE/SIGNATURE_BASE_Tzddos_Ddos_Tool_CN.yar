import "pe"

rule SIGNATURE_BASE_Tzddos_Ddos_Tool_CN
{
	meta:
		description = "Disclosed hacktool set - file tzddos"
		author = "Florian Roth (Nextron Systems)"
		id = "bf2bfc7b-4db8-5d35-a312-2530a42985d5"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1046-L1065"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d4c517eda5458247edae59309453e0ae7d812f8e"
		logic_hash = "fed09a8586f9b573e46871efa71082f4573d2bd069fde9cc2928b267d0025bab"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "for /f %%a in (host.txt) do (" ascii
		$s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
		$s2 = "del host.txt /q" fullword ascii
		$s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
		$s4 = "start Http.exe %%a %http%" fullword ascii
		$s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii
		$s6 = "del Result.txt s2.txt s1.txt " fullword ascii

	condition:
		all of them
}
