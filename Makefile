.PHONY: all clean paper

all: paper

paper:
	$(MAKE) -C paper all

clean:
	$(MAKE) -C paper clean
