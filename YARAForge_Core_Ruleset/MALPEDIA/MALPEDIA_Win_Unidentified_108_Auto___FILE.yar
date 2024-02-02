rule MALPEDIA_Win_Unidentified_108_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "91d0ee32-15d3-5f4b-b0c7-e219a3fb056f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_108"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_108_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "bc8d7e8276cd214c62a44b786052de8d0d6c82c70c52e7e29cb797627cab2825"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 488d05c7580100 4a8b0ce8 42385cf938 7d4f 400fbece 4084f6 }
		$sequence_1 = { 0f8493010000 488d2d3a100100 83635000 83632c00 e9???????? 48ff4318 837b2800 }
		$sequence_2 = { 660feb0d???????? 4c8d0d44950000 f20f5cca f2410f590cc1 660f28d1 660f28c1 4c8d0d0b850000 }
		$sequence_3 = { 7426 488d5540 803201 488d5201 41ffc0 488d4540 498bcc }
		$sequence_4 = { 4c8d05a8310100 83e23f 488d14d2 498b04c0 f644d03801 }
		$sequence_5 = { 488d1dd6db0100 458bc5 498bcc 48ffc1 4438040b 75f7 4885c9 }
		$sequence_6 = { 458bc5 498bc4 90 48ffc0 44380401 }
		$sequence_7 = { 0fb6557f 4889451f 83f201 488d05dbc90000 49c1e302 4889452f 03d2 }
		$sequence_8 = { 488d9588000000 803201 488d5201 41ffc0 488d8588000000 }
		$sequence_9 = { 7350 488bca 4c8d051d310100 83e13f 488bc2 48c1f806 }

	condition:
		7 of them and filesize <307200
}