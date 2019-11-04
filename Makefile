# SPDX-License-Identifier: GPL-2.0-only

CFLAGS	:= -fPIC -c -g
LDFLAGS	:= -shared -g
OBJ	:= libpam-chvrf.o
SRC	:= source/changevrf.c
TARGET	:= libpam-chvrf.so

all: $(TARGET)

libpam-chvrf.o: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(OBJ)

libpam-chvrf.so: $(OBJ)
	$(CC) $(OBJ) -shared -o $(TARGET)

install: $(TARGET)
	mkdir -p $(DESTDIR)/lib/security
	install -m644 $(TARGET) $(DESTDIR)/lib/security
	mkdir -p $(DESTDIR)/usr/share/pam-configs
	install -m644 debian/libpam-chvrf.pam-auth-update \
		$(DESTDIR)/usr/share/pam-configs/libpam-chvrf

clean:
	rm -f $(OBJ) $(TARGET)
