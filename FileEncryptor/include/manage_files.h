#pragma once

#include <fstream>
#include <iostream>

namespace file {

    void saveToFile(const std::string &filename, const std::string &data) {
        std::ofstream file(filename);
        if (file.is_open()) {
            file << data;
            file.close();
        } else {
            std::cerr << "Unable to open file: " << filename << std::endl;
        }
    }

    std::string loadFromFile(const std::string &filename) {
        std::ifstream file(filename);
        if (file.is_open()) {
            std::string data((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
            file.close();
            return data;
        } else {
            std::cerr << "Unable to open file: " << filename << std::endl;
            return "";
        }
    }
}