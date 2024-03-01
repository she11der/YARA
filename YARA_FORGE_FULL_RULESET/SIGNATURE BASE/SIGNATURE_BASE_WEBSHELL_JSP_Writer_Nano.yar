import "math"

rule SIGNATURE_BASE_WEBSHELL_JSP_Writer_Nano : FILE
{
	meta:
		description = "JSP file writer"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "422a18f2-d6d4-5b42-be15-1eafe44e01cf"
		date = "2021-01-24"
		modified = "2023-04-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_webshells.yar#L5605-L5686"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ac91e5b9b9dcd373eaa9360a51aa661481ab9429"
		hash = "c718c885b5d6e29161ee8ea0acadb6e53c556513"
		hash = "9f1df0249a6a491cdd5df598d83307338daa4c43"
		hash = "5e241d9d3a045d3ade7b6ff6af6c57b149fa356e"
		logic_hash = "8cf47fe03845f39d7ff7ba4ad8f44a879cdf1aba0869921c5adf6d7490bc4174"
		score = 75
		quality = 48
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$payload1 = ".write" wide ascii
		$payload2 = "getBytes" fullword wide ascii
		$payload3 = ".decodeBuffer" wide ascii
		$payload4 = "FileOutputStream" fullword wide ascii
		$logger1 = "getLogger" fullword ascii wide
		$logger2 = "FileHandler" fullword ascii wide
		$logger3 = "addHandler" fullword ascii wide
		$input1 = "getParameter" fullword ascii wide
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide
		$jw_sus1 = /getParameter\("."\)/ ascii wide
		$jw_sus4 = "yoco" fullword ascii wide
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide

	condition:
		( any of ($input*) and any of ($req*)) and ( filesize <200 or ( filesize <1000 and any of ($jw_sus*))) and ($cjsp_short1 at 0 or any of ($cjsp_long*) or $cjsp_short2 in ( filesize -100.. filesize ) or ($cjsp_short2 and ($cjsp_short1 in (0..1000) or $cjsp_short1 in ( filesize -1000.. filesize )))) and (2 of ($payload*) or all of ($logger*))
}
