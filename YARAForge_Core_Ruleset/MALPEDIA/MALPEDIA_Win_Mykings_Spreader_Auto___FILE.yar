rule MALPEDIA_Win_Mykings_Spreader_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "96a12e80-b15f-580e-920d-d6c0d35464b0"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mykings_spreader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mykings_spreader_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "1bcd674173fea4b83a2f4219e8f61306a972490f94a89cfaf5e1f466fdec8eff"
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
		$sequence_0 = { 7519 51 55 8bce e8???????? 6a00 6a00 }
		$sequence_1 = { 8b1e ff938c000000 8b0424 8b5014 85d2 7507 bf00000000 }
		$sequence_2 = { e8???????? 837e1800 7439 8b4620 c1e003 89c7 8b4618 }
		$sequence_3 = { 89c1 c745f401000000 3b4df4 723d ff4df4 8d7600 ff45f4 }
		$sequence_4 = { 68???????? 50 ff15???????? a3???????? 83c0fe 40 40 }
		$sequence_5 = { 8942fc 89d8 c1f81f 8b1424 8b7208 8b4a0c 29de }
		$sequence_6 = { eb02 b300 e8???????? 8d45cc e8???????? c745cc00000000 58 }
		$sequence_7 = { 33d2 b9???????? 8bc2 8bf2 c1f805 83e61f 8b0485a02e4100 }
		$sequence_8 = { 89d8 29f0 85c0 7e39 8b55f4 85d2 7505 }
		$sequence_9 = { 8b7508 8b36 8975c8 8b7d08 8b7f04 }

	condition:
		7 of them and filesize <1581056
}