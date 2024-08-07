## 2024.08.07 Release (v2.5):
- Add in JSON health check output support.
- Fix a bug that occasionally caused a crash on startup if the logger thread didn't quite initialize quick enough
- Fix a second related bug that occasionally caused a crash on shutdown if the logger thread didn't terminate in the right order.

## 2023.10.03 Release (v2.4):
- Replace flow caches with version based on Boost's concurrent_flat_map, improving performance and reducing CPU usage due to time spent waiting for locks.
- Standardized logging into its own class and thread, with improved configuration options
- General code cleanup - broke out per ENI handling to its own class (GeneveHandlerENI) which simplified code a fair bit.

## 2023.06.07 Release:
- Add NO_RETURN_TRAFFIC define by request - this strips out some of the internal tracking and removes the ability to send packets back to GWLB, but increases performance on incoming packet handling.

## 2022.11.17 Release:
- **Update to support IPv6 payloads from GWLB**
- Updated CMakeLists file to cleanly separate Debug and Release build options
- Rearrange initializers to cleanup some harmless ```-Wreorder``` warnings, and reorder a couple fields to optimize memory access
- Update packet hashing algorithm to be in one place (utils.h, defined inline), along with adding stats as to how the hash algorithm is performing to the status webpage when the debug flag is on. Thusfar in testing, the simple add-all-fields algorithm does well with avoiding collisions and is fast.
- Updated help on script parameters, as suggested by liujunhui74
- Added recognizing the flow in both directions when seen the first time, as suggested by liujunhui74
- Cleaned up debugging output to be consistent, and added milliseconds to the timestamp
- Update shutdown process to have all threads stop processing, then shutdown. In high PPS testing, there would occasionally be a race condition in shutting down that would result in a use-after-free error which this resolves.
- Updated the hashing for PacketHeader classes to extend std::hash instead of providing their own additional classes to std::unordered_map for cleaner operation.
- Reserve 3 GENEVE header options by default when processing a GENEVE packet, avoiding an unnecessary realloc due to dynamic vector expansion.
- Fixed an issue where in high PPS testing, the UDP thread would take a long time to shutdown (due to not checking for the shutdown requested flag in the inner packet processing loop)
- Replaced some ```sprintf```s with ```snprintf```s in ```hexDump()``` for safety

## 2022.05.13 Release:
- Initial version
