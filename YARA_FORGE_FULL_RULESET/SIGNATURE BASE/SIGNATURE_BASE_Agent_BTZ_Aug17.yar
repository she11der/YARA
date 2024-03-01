import "pe"

rule SIGNATURE_BASE_Agent_BTZ_Aug17 : FILE
{
	meta:
		description = "Detects Agent.BTZ"
		author = "Florian Roth (Nextron Systems)"
		id = "31804208-3edb-554b-8820-e682db647435"
		date = "2017-08-07"
		modified = "2023-12-05"
		reference = "http://www.intezer.com/new-variants-of-agent-btz-comrat-found/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_agent_btz.yar#L54-L73"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "cf4fc7820d516cf0322bf25460301b4d04f914814fc2a069164814dd4e1158be"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "6ad78f069c3619d0d18eef8281219679f538cfe0c1b6d40b244beb359762cf96"
		hash2 = "49c5c798689d4a54e5b7099b647b0596fb96b996a437bb8241b5dd76e974c24e"
		hash3 = "e88970fa4892150441c1616028982fe63c875f149cd490c3c910a1c091d3ad49"

	strings:
		$s1 = "stdole2.tlb" fullword ascii
		$s2 = "UnInstallW" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and all of them and pe.exports("Entry") and pe.exports("InstallW") and pe.exports("UnInstallW"))
}
