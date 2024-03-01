rule SIGNATURE_BASE_CN_Honker_Webshell_Injection_Transit_Jmpost : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jmPost.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "892f747e-6065-5baf-b928-8d69d8792483"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L371-L386"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f80ec26bbdc803786925e8e0450ad7146b2478ff"
		logic_hash = "6c7f52cf7ff6df9867ea2c46cd8f40ef0e077d4e1d9033cde0649a209bffe21b"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii
		$s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii

	condition:
		filesize <9KB and all of them
}
