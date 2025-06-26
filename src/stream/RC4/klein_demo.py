#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/RC4/klein_demo.py'
#   RC4 decryption via Klein attack
#       
#   The method of this attack was pulled form several online sources 
#   and then Claude AI was used to polish it up + clean up the debug 
#   and print messages. Because Claude AI's printouts were much prettier
#   than mine, I used it to redo all of them. Especially the status messages
#
#   The thresholds for relevance have been adjusted because of the bias
#   occuring when looking at the key discovery from the comparison directly
#   to the ground truth (key). Discussion of this is in the README.
#
#   Author(s): Lauren Linkous
#   Last update: June 25, 2025
##--------------------------------------------------------------------\

import pandas as pd
from collections import Counter

# Import the real RC4 implementation
from encrypt import encrypt

class KleinDemo:

    def __init__(self):
        # Does not follow the typical decrypt class format because this is a 1-off demo

        self.debug = True


        
    def generate_related_keystreams(self, base_key, num_samples, keystream_length=64):
        # Klein's attack works by analyzing a large number of keystreams and finding statistically signifigant
        # relations between letters of potential keys and the cipher stream.

        # This function generates keystreams with the same key. 


        print(f"🔑 Generating {num_samples} keystreams from related keys")
        print(f"   Base key: '{base_key}' - analyzing correlations with variations")
        
        keystreams = []
        keys_used = []
        s_boxes = []
        
        #  opt_df structure for the encrypt() class call
        # this is a standardization for this repo.
        # We are using the encrypt() class due to the sheer amount of data that needs to be generated.
        options = pd.DataFrame({
            'KEY': [''],  # Will be set for each iteration
            'OUTPUT_FORMAT': ['BYTES'],
            'SHOW_STEPS': [False]
        })
        
        for i in range(num_samples):
            # Generate related key - Klein's attack often uses keys that differ in known ways
            if i == 0:
                # First keystream uses the exact target key
                current_key = base_key
            else:
                # Generate variations of the key for statistical analysis
                # Klein's attack exploits the fact that similar keys produce correlated outputs
                current_key = self.generate_key_variant(base_key, i)
            
            keys_used.append(current_key)
            
            # Create cipher instance
            cipher = encrypt(None, options)
            
            # Initialize RC4 to get the S-box after KSA
            initial_s_box = cipher.initialize_rc4(current_key)
            s_boxes.append(initial_s_box.copy())
            
            # Generate keystream
            keystream_bytes = cipher.generate_keystream(keystream_length)
            keystream = list(keystream_bytes)
            keystreams.append(keystream)
            
            if (i + 1) % 1000 == 0:
                print(f"  Generated {i + 1}/{num_samples} keystreams")
        
        return keystreams, s_boxes, keys_used
    


    def generate_key_variant(self, base_key, variant_id):
        # Generate a KEY VARIANT
        # Since we have control over the data source, we can adjust the key and watch 
        # how the cipherstream changes (mathematically)


        # Convert base key to bytes
        base_bytes = list(base_key.encode('utf-8'))
        
        # Create variants by:
        # 1. Changing one byte at a time
        # 2. Adding random prefixes/suffixes  
        # 3. Bit-flipping operations
        
        variant_type = variant_id % 4
        
        if variant_type == 0:
            # Single byte modification
            if len(base_bytes) > 0:
                pos = variant_id % len(base_bytes)
                modified_bytes = base_bytes.copy()
                modified_bytes[pos] = (modified_bytes[pos] + 1) % 256
                return bytes(modified_bytes).decode('utf-8', errors='replace')
        
        elif variant_type == 1:
            # Add single byte prefix
            prefix_byte = (variant_id // 4) % 256
            return chr(prefix_byte) + base_key
        
        elif variant_type == 2:
            # Add single byte suffix
            suffix_byte = (variant_id // 4) % 256
            return base_key + chr(suffix_byte)
        
        else:
            # Bit flip in first byte
            if len(base_bytes) > 0:
                modified_bytes = base_bytes.copy()
                bit_pos = variant_id % 8
                modified_bytes[0] = modified_bytes[0] ^ (1 << bit_pos)
                return bytes(modified_bytes).decode('utf-8', errors='replace')
        
        # Fallback
        return base_key + chr((variant_id % 26) + ord('A'))
    
    def analyze_klein_correlations(self, keystreams, keys_used, target_key):
        # This is the main part of the attack. Klein's core discovery was that the
        # first ~16 to 32 bytes have a statistically signifigant coorelation to the 
        # key bytes. 


        print(f"\n🔍 ANALYZING KLEIN'S KEY-KEYSTREAM CORRELATIONS")
        print("-" * 50)
        
        target_bytes = target_key.encode('utf-8')
        correlations = {}
        
        # Klein's insight: First ~16 to 32 keystream bytes have statistical correlations with key
        # This can be 16 and still get some values back (see README RC4 example), but its more interesting to run
        # the full thing.
        for ks_pos in range(min(32, len(keystreams[0]))):
            print(f"\nAnalyzing keystream position {ks_pos}:")
            
            # Extract all values at this keystream position
            ks_values = [ks[ks_pos] for ks in keystreams]
            
            # Klein's method: Look for bias toward specific key bytes
            for key_pos in range(len(target_bytes)):
                target_key_byte = target_bytes[key_pos]
                
                # Count how often this key byte appears in this keystream position
                matches = sum(1 for val in ks_values if val == target_key_byte)
                total = len(ks_values)
                observed_prob = matches / total
                expected_prob = 1.0 / 256  # Random chance
                
                bias_strength = observed_prob / expected_prob
                
                # Show all correlations, even weak ones, for debugging
                if matches > 0:
                    print(f"    Key[{key_pos}] = 0x{target_key_byte:02X} ('{chr(target_key_byte) if 32 <= target_key_byte <= 126 else '?'}') "
                          f"appears {matches}/{total} times (prob: {observed_prob:.4f}, bias: {bias_strength:.2f}x)")
        
        if correlations:
            print(f"\n🔗 Found {sum(len(v) for v in correlations.values())} significant correlations")
        else:
            print(f"\n❌ No significant correlations detected")
        
        return correlations
    
    def klein_key_recovery(self, keystreams, correlations, target_key_length):
        # The key recovery using the discovered correlations.
        # Most of the time this is going to get NOTHING with our demos. 
        # This implementation is not intelligent enough to modify the tested keys based on 
        # the signifigant relations.
        # HOWEVER, it works well enough for the demo.


        print(f"\n🔓 KLEIN'S KEY RECOVERY USING CORRELATIONS")
        print("-" * 50)
        
        recovered_key = []
        confidence_scores = []
        
        for key_pos in range(target_key_length):
            print(f"\n🎯 Recovering key byte {key_pos}:")
            
            candidate_scores = {}
            
            # For each possible byte value
            for candidate in range(256):
                score = 0
                
                # Check all keystream positions for correlations with this candidate
                for ks_pos, ks_correlations in correlations.items():
                    if key_pos in ks_correlations:
                        correlation = ks_correlations[key_pos]
                        
                        # If this candidate matches the correlated key byte, give massive score
                        if candidate == correlation['key_byte']:
                            # Weight by bias strength - strong correlations get huge scores
                            correlation_score = correlation['bias_strength'] * 1000
                            score += correlation_score
                
                # Secondary scoring: frequency analysis of candidate in keystreams
                # But weight this much lower than direct correlations
                all_ks_values = [val for ks in keystreams for val in ks[:8]]  # First 8 bytes
                candidate_freq = sum(1 for val in all_ks_values if val == candidate)
                freq_score = (candidate_freq / len(all_ks_values)) * 10  # Lower weight
                score += freq_score
                
                candidate_scores[candidate] = score
            
            # Find best candidate
            if candidate_scores:
                sorted_candidates = sorted(candidate_scores.items(), key=lambda x: x[1], reverse=True)
                
                best_candidate = sorted_candidates[0][0]
                best_score = sorted_candidates[0][1]
                second_best_score = sorted_candidates[1][1] if len(sorted_candidates) > 1 else 0
                
                confidence = best_score - second_best_score
                
                recovered_key.append(best_candidate)
                confidence_scores.append(confidence)
                
                # Show top candidates
                print(f"  Top candidates:")
                for i, (byte_val, score) in enumerate(sorted_candidates[:5]):
                    char_rep = chr(byte_val) if 32 <= byte_val <= 126 else f'\\x{byte_val:02x}'
                    print(f"    {i+1}. 0x{byte_val:02X} ('{char_rep}') - score: {score:.3f}")
                
                print(f"  → Selected: 0x{best_candidate:02X}, confidence: {confidence:.3f}")
            else:
                recovered_key.append(0)
                confidence_scores.append(0)
                print(f"  → No clear candidate found")
        
        return recovered_key, confidence_scores
    

    
    def analyze_first_bytes_bias(self, keystreams):
        # This was a Claude AI suggestion
        # Pulling this analysis out to a different function because these
        # first couple bytes are far more signifigant that some sources state
        # (The actual disclosure is pretty clear about it though.)
        # 

        print(f"\n🔍 ANALYZING FIRST BYTES BIAS (RC4 Weakness)")
        print("-" * 50)
        
        # Check if byte 0 = 0 is more likely (known RC4 bias)
        first_bytes = [ks[0] for ks in keystreams]
        zero_count = sum(1 for b in first_bytes if b == 0)
        zero_prob = zero_count / len(first_bytes)
        expected_prob = 1.0 / 256
        
        print(f"First byte = 0: {zero_count}/{len(first_bytes)} ({zero_prob:.4f})")
        print(f"Expected probability: {expected_prob:.4f}")
        
        if zero_prob > expected_prob * 1.5:
            print(f"✅ Confirmed RC4 first-byte bias (factor: {zero_prob/expected_prob:.2f}x)")
        else:
            print(f"❌ No significant first-byte bias detected")
        
        # Check second byte biases
        if len(keystreams[0]) > 1:
            second_bytes = [ks[1] for ks in keystreams]
            second_counter = Counter(second_bytes)
            most_common = second_counter.most_common(5)
            
            print(f"\nSecond byte distribution (top 5):")
            for byte_val, count in most_common:
                prob = count / len(second_bytes)
                bias = prob / expected_prob
                print(f"  0x{byte_val:02X}: {count}/{len(second_bytes)} ({prob:.4f}, bias: {bias:.2f}x)")
        
        return {
            'first_byte_zero_prob': zero_prob,
            'first_byte_bias_factor': zero_prob / expected_prob,
            'second_byte_dist': Counter([ks[1] for ks in keystreams]) if len(keystreams[0]) > 1 else {}
        }




    def evaluate_attack_success(self, target_key, recovered_key, confidence_scores):
        # How successful was the attack?
        # This function compares how well the recovered key matches the target key
        # Hint: Usually not well, about random.

        """
        Evaluate how successful the attack was
        """
        print(f"\n" + "=" * 60)
        print("ATTACK EVALUATION")
        print("=" * 60)
        
        target_bytes = target_key.encode('utf-8')
        
        print(f"Target key:    '{target_key}'")
        print(f"Target bytes:  {' '.join(f'{b:02X}' for b in target_bytes)}")
        
        # Build recovered key string
        recovered_str = ""
        recovered_hex = []
        correct_count = 0
        
        for i, (recovered_byte, confidence) in enumerate(zip(recovered_key, confidence_scores)):
            if i < len(target_bytes):
                correct = recovered_byte == target_bytes[i]
                if correct:
                    correct_count += 1
                
                char_rep = chr(recovered_byte) if 32 <= recovered_byte <= 126 else f'\\x{recovered_byte:02x}'
                recovered_str += char_rep
                recovered_hex.append(f"{recovered_byte:02X}")
                
                status = "✅" if correct else "❌"
                print(f"Position {i}: 0x{recovered_byte:02X} vs 0x{target_bytes[i]:02X} "
                      f"(conf: {confidence:.3f}) {status}")
        
        print(f"\nRecovered key: '{recovered_str}'")
        print(f"Recovered hex: {' '.join(recovered_hex)}")
        
        success_rate = (correct_count / len(target_bytes)) * 100
        print(f"\n🎯 SUCCESS RATE: {correct_count}/{len(target_bytes)} bytes correct ({success_rate:.1f}%)")
        
        return success_rate
    
    def run_real_attack(self, target_key, num_samples=1000):
        # run the complete Klein attack

        print("=" * 80)
        print("KLEIN'S RC4 ATTACK")
        print("=" * 80)
        print("Based on: Attacks on the RC4 stream cipher by Andreas Klein (2005)")
        print("Method: Analyze correlations between key bytes and early keystream bytes")
        print()
        
        # Step 1: Generate related keystreams
        print(f"🎯 TARGET KEY: '{target_key}' ({len(target_key)} bytes)")
        keystreams, s_boxes, keys_used = self.generate_related_keystreams(target_key, num_samples)
        
        # Step 2: Analyze Klein's correlations
        correlations = self.analyze_klein_correlations(keystreams, keys_used, target_key)
        
        # Step 3: Analyze first bytes bias (RC4 weakness)
        first_byte_analysis = self.analyze_first_bytes_bias(keystreams)
        
        # Step 4: Attempt key recovery
        recovered_key, confidence_scores = self.klein_key_recovery(keystreams, correlations, len(target_key))
        
        # Step 5: Evaluate success
        success_rate = self.evaluate_attack_success(target_key, recovered_key, confidence_scores)
        
        print(f"\n📊 ATTACK SUMMARY:")
        print(f"• Keystreams analyzed: {len(keystreams)}")
        print(f"• Correlations found: {sum(len(v) for v in correlations.values())}")
        print(f"• First-byte bias factor: {first_byte_analysis['first_byte_bias_factor']:.2f}x")
        
        return {
            'target_key': target_key,
            'recovered_key': recovered_key,
            'success_rate': success_rate,
            'samples_used': num_samples,
            'correlations_found': sum(len(v) for v in correlations.values()),
            'first_byte_bias': first_byte_analysis['first_byte_bias_factor'],
            'confidence_scores': confidence_scores
        }



def run_comprehensive_analysis():
    # Loop through multiple test cases
    # There needs to be 10s of thousands of data samples for proper analysis. 
    # There is a roll off point.


    print("🎓 KLEIN'S RC4 ATTACK - COMPREHENSIVE ANALYSIS")
    print("=" * 80)
    print("Using Klein's attack methodology")
    print("Analyzing key-keystream correlations with related keys")
    print()
    
    # Test cases with higher sample sizes for better correlation detection
    test_cases = [
        {"key": "ATTACK", "samples": 50000, "description": "6-char alphabetic key"},
        {"key": "SECRET", "samples": 50000, "description": "6-char common word"},
        {"key": "TEST123", "samples": 75000, "description": "7-char alphanumeric"},
        {"key": "KEY", "samples": 100000, "description": "3-char short key"},
        {"key": "LONGPASSWORD", "samples": 450000, "description": "12-char long key"},
        {"key": "RC4", "samples": 25000, "description": "3-char technical term"},
        {"key": "DEMO2025", "samples": 200000, "description": "8-char mixed key"}
    ]
    
    attack = KleinDemo()
    results = []
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{'='*80}")
        print(f"TEST CASE {i}/{len(test_cases)}: {test_case['description']}")
        print(f"Key: '{test_case['key']}' | Samples: {test_case['samples']}")
        print('='*80)
        
        try:
            result = attack.run_real_attack(test_case['key'], test_case['samples'])
            result['description'] = test_case['description']
            results.append(result)
            
            print(f"\n⏱️  Test case {i} complete. Moving to next...")
            
        except Exception as e:
            print(f"❌ Test case {i} failed with error: {e}")
            import traceback
            traceback.print_exc()
            results.append({
                'target_key': test_case['key'],
                'recovered_key': [],
                'success_rate': 0,
                'samples_used': test_case['samples'],
                'correlations_found': 0,
                'first_byte_bias': 1.0,
                'confidence_scores': [],
                'description': test_case['description'],
                'error': str(e)
            })
    
    # Generate final report
    generate_final_report(results)
    
    return results



def generate_final_report(results):
    # Generated report from Claude AI (much prettier than my attempt :) )
    
    print("\n" + "="*80)
    print("COMPREHENSIVE KLEIN'S ATTACK ANALYSIS REPORT")
    print("="*80)
    
    # Filter successful results
    valid_results = [r for r in results if 'error' not in r]
    
    if not valid_results:
        print("❌ No successful attacks to analyze")
        return
    
    # Overall statistics
    total_tests = len(valid_results)
    successful_attacks = sum(1 for r in valid_results if r['success_rate'] >= 15)  # Realistic threshold
    partial_successes = sum(1 for r in valid_results if 5 <= r['success_rate'] < 15)
    failures = sum(1 for r in valid_results if r['success_rate'] < 5)
    
    avg_success_rate = sum(r['success_rate'] for r in valid_results) / len(valid_results)
    total_samples = sum(r['samples_used'] for r in valid_results)
    
    print(f"\n📈 OVERALL ATTACK EFFECTIVENESS:")
    print(f"   Total valid attacks:     {total_tests}")
    print(f"   Successful (≥15%):       {successful_attacks} ({successful_attacks/total_tests*100:.1f}%)")
    print(f"   Partial (5-14%):         {partial_successes} ({partial_successes/total_tests*100:.1f}%)")
    print(f"   Failed (<5%):            {failures} ({failures/total_tests*100:.1f}%)")
    print(f"   Average success rate:    {avg_success_rate:.1f}%")
    print(f"   Total samples analyzed:  {total_samples:,}")
    
    # Detailed results
    print(f"\n📋 DETAILED RESULTS:")
    print("-" * 80)
    print(f"{'Key':<12} {'Samples':<8} {'Success':<8} {'Corr':<5} {'Bias':<6} {'Status'}")
    print("-" * 80)
    
    for result in valid_results:
        key = result['target_key']
        samples = f"{result['samples_used']:,}"
        success = f"{result['success_rate']:.1f}%"
        correlations = result['correlations_found']
        bias = f"{result['first_byte_bias']:.2f}x"
        
        if result['success_rate'] >= 15:
            status = "✅ Success"
        elif result['success_rate'] >= 5:
            status = "⚠️  Partial"
        else:
            status = "❌ Failed"
        
        print(f"{key:<12} {samples:<8} {success:<8} {correlations:<5} {bias:<6} {status}")
    
    # Key insights
    print(f"\n💡 KEY INSIGHTS:")
    
    best_result = max(valid_results, key=lambda x: x['success_rate'])
    print(f"   🏆 Best attack:          '{best_result['target_key']}' ({best_result['success_rate']:.1f}%)")
    
    # Correlation analysis
    high_corr_attacks = [r for r in valid_results if r['correlations_found'] > 5]
    if high_corr_attacks:
        high_corr_avg = sum(r['success_rate'] for r in high_corr_attacks) / len(high_corr_attacks)
        print(f"   🔗 High correlation keys: {high_corr_avg:.1f}% average success")
    
    # Bias analysis
    high_bias_attacks = [r for r in valid_results if r['first_byte_bias'] > 2.0]
    if high_bias_attacks:
        high_bias_avg = sum(r['success_rate'] for r in high_bias_attacks) / len(high_bias_attacks)
        print(f"   📈 High bias keys:       {high_bias_avg:.1f}% average success")
    
    print(f"\n🎯 REALISTIC EXPECTATIONS:")
    print(f"   Klein's attack is extremely challenging and typically requires:")
    print(f"   • Millions of related keystreams")
    print(f"   • Sophisticated statistical analysis")
    print(f"   • Optimal key relationships")
    print(f"   • Advanced correlation detection")
    print(f"   ")
    print(f"   This educational implementation demonstrates the theoretical")
    print(f"   foundation but shows why RC4 remained unbroken for so long!")



if __name__ == "__main__":
    # Run the comprehensive analysis from here instead of from a test file
    results = run_comprehensive_analysis()