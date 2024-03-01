rule MALPEDIA_Win_Rapid_Ransom_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ffd06a30-064b-5d5c-9708-094ba6b3f858"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rapid_ransom"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.rapid_ransom_auto.yar#L1-L164"
		license_url = "N/A"
		logic_hash = "467069894b412bd66ec7bc5db00e763aed4734a1d880a5b3cc4cb8b392b71ec1"
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
		$sequence_0 = { 50 6801000004 6800a40000 ff75f8 }
		$sequence_1 = { 83ec10 53 56 57 8bf9 32db 8bf2 }
		$sequence_2 = { 83ec1c 53 57 8bf9 8bc2 }
		$sequence_3 = { ff15???????? 6a00 ff75f8 ff15???????? 5e 5f 8ac3 }
		$sequence_4 = { 7509 803a00 0f840c010000 8d742464 b8???????? 84db }
		$sequence_5 = { 56 8bf2 8975fc 57 8bf9 85db }
		$sequence_6 = { e8???????? 83c430 8d45f4 6800010000 }
		$sequence_7 = { 7425 ff7514 8b542418 8bce ff7510 c644241701 57 }
		$sequence_8 = { 0f8483000000 eb7d 8b1c9df8584100 6800080000 }
		$sequence_9 = { 740e 50 e8???????? 83a6e8d0410000 59 83c604 }
		$sequence_10 = { 8be5 5d c3 ff75e0 e8???????? 53 e8???????? }
		$sequence_11 = { eb72 8d04cd00000000 2bc1 46 8935???????? c6048564d3410001 893c856cd34100 }
		$sequence_12 = { 6804010000 8d85a4feffff 8bf1 6a00 50 }
		$sequence_13 = { 40 c745ecf54e4000 894df8 8945fc 64a100000000 8945e8 }
		$sequence_14 = { 83c9ff c7430c01000000 c7431000000000 eb2f }

	condition:
		7 of them and filesize <286720
}
