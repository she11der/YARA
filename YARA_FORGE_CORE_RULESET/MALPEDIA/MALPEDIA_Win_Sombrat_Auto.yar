rule MALPEDIA_Win_Sombrat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "829e34aa-1da2-5a33-9238-c1cc0c096058"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sombrat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.sombrat_auto.yar#L1-L149"
		license_url = "N/A"
		logic_hash = "a1432e014afc208b0318e2ead477453bc5bd4bddb98bd4c2d60380403a2290c4"
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
		$sequence_0 = { 014114 8b7508 837df800 8b5df4 }
		$sequence_1 = { 01041e 8b4508 42 8d7308 }
		$sequence_2 = { 0144244a 894e0c ffb72c010000 ff15???????? }
		$sequence_3 = { 01420c 8b11 294210 8b09 }
		$sequence_4 = { 0145e4 8b55f8 83c40c 294644 }
		$sequence_5 = { 0000 e8???????? c70424???????? 8d5f0c 68???????? }
		$sequence_6 = { 7514 8b4610 8d8de4fffeff 2b4618 03c3 }
		$sequence_7 = { 014114 014620 f6460c04 8945e0 742d }
		$sequence_8 = { 015f08 33c0 488b4c2470 4833cc }
		$sequence_9 = { 0145f1 4533c9 4533c0 488b16 }
		$sequence_10 = { 016b08 488d05dc980500 41b9e7160000 4889442420 }
		$sequence_11 = { 015f08 83bfd800000016 0f856c020000 488b87c8000000 }
		$sequence_12 = { 016b08 33c0 e9???????? 33ff }
		$sequence_13 = { 01448c20 48ffc1 493bc9 7cf1 }
		$sequence_14 = { 015f08 33c0 e9???????? 488b4760 }
		$sequence_15 = { 015f08 488bcf e8???????? 8bf0 }

	condition:
		7 of them and filesize <1466368
}
