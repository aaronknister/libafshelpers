char * afshelpers_helpers_nextLine(char *line) {
        while(*line != '\n')
                line++;
        line++;
        return line;
}

int afshelper_setpag() {
       /* Set the PAG */
        return setpag();

}
