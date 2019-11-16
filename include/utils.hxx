
#ifndef __utils__hxx__
#define __utils__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <string>

std::u16string x_convert_utf8_to_utf16(const std::string &src);
std::string x_convert_utf16_to_utf8(const std::u16string &src);


#endif /* __utils__hxx__ */

