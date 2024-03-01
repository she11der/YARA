rule MALPEDIA_Win_Rover_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1dedd2f8-89d8-5b82-937e-e4187a543962"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rover"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.rover_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "6367e2cdf56f70609689c8633064a076a7b96ec3143349e9ae15d5e0ca66c168"
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
		$sequence_0 = { 6800120000 885c247b ff15???????? 85c0 0f8422010000 8b35???????? 8d542460 }
		$sequence_1 = { ff15???????? 8d4c2404 c684249c00000000 ff15???????? 8d8c24a4000000 c784249c000000ffffffff }
		$sequence_2 = { 83ed01 0f8464010000 83ed04 0f845b010000 83bba402000000 8b6a28 896c240c }
		$sequence_3 = { 85db 0f856f030000 8b471c 85c0 7421 50 8d442414 }
		$sequence_4 = { 8bf0 83c404 3bf3 7537 a1???????? 8b4824 8d542438 }
		$sequence_5 = { 50 8b442458 68???????? 50 e8???????? 83c410 85c0 }
		$sequence_6 = { 8b8fb0050000 8d6b50 89442410 8987b0050000 8b85a8000000 8bd0 80e215 }
		$sequence_7 = { 83e802 7426 83e815 740f 683f270000 ff15???????? 83c8ff }
		$sequence_8 = { 83c40c c3 6a2f 57 ffd6 83c408 85c0 }
		$sequence_9 = { 57 e8???????? 56 e8???????? 83c40c c744242c04000000 }

	condition:
		7 of them and filesize <704512
}
