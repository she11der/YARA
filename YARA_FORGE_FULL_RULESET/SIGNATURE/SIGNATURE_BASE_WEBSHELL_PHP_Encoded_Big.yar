import "math"

rule SIGNATURE_BASE_WEBSHELL_PHP_Encoded_Big : FILE
{
	meta:
		description = "PHP webshell using some kind of eval with encoded blob to decode"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "c3bb7b8b-c554-5802-8955-c83722498f8b"
		date = "2021-02-07"
		modified = "2023-07-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_webshells.yar#L2337-L2424"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1d4b374d284c12db881ba42ee63ebce2759e0b14"
		hash = "fc0086caee0a2cd20609a05a6253e23b5e3245b8"
		hash = "b15b073801067429a93e116af1147a21b928b215"
		hash = "74c92f29cf15de34b8866db4b40748243fb938b4"
		hash = "042245ee0c54996608ff8f442c8bafb8"
		logic_hash = "170d9f148bf824b30068aa5a820dd57b2db54a75fcedaf5a6d6ed9f704f6debf"
		score = 50
		quality = -829
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$new_php1 = /<\?=[\w\s@$]/ wide ascii
		$new_php2 = "<?php" nocase wide ascii
		$new_php3 = "<script language=\"php" nocase wide ascii
		$php_short = "<?"
		$cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\n\t ]{0,500}(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
		$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii

	condition:
		filesize <1000KB and ( any of ($new_php*) or $php_short at 0) and ( any of ($cpayload*) or all of ($m_cpayload_preg_filter*)) and ( filesize >2KB and (math.entropy(500, filesize -500)>=5.7 and math.mean(500, filesize -500)>80 and math.deviation(500, filesize -500,89.0)<24) or (math.entropy(500, filesize -500)>=7.7 and math.mean(500, filesize -500)>120 and math.mean(500, filesize -500)<136 and math.deviation(500, filesize -500,89.0)>65))
}
