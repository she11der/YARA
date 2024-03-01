rule SIGNATURE_BASE_FVEY_Shadowbroker_Gr_Gr
{
	meta:
		description = "Auto-generated rule - file gr.notes"
		author = "Florian Roth (Nextron Systems)"
		id = "c233159d-8d78-575b-b32b-21f704debfe2"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fvey_shadowbroker_dec16.yar#L88-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "facce45a335d7ca799d68fc26ee2bf5682cec0914502482189cd6aa496cba489"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b2b60dce7a4cfdddbd3d3f1825f1885728956bae009de3a307342fbdeeafcb79"

	strings:
		$s4 = "delete starting from: (root) LIST (root)" fullword ascii

	condition:
		1 of them
}
