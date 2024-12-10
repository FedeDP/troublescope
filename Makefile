# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2024 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#


NAME := troublescope
OUTPUT := lib$(NAME).so

all: $(OUTPUT)

.PHONY: clean
clean:
	rm -rf build $(OUTPUT)

# This Makefile requires CMake installed on the system
.PHONY: $(OUTPUT)
$(OUTPUT):
	cmake -B build -S . && make -C build/ troublescope -j6 && cp build/$(OUTPUT) $(OUTPUT)

readme:
	@$(READMETOOL) -p ./$(OUTPUT) -f README.md