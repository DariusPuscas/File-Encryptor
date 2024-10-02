#pragma once
/*
#include <aws/core/Aws.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <aws/s3/model/GetObjectRequest.h>

void uploadEncryptedFileToS3(const std::string& bucketName, const std::string& keyName, const std::string& encryptedFilePath) {
    Aws::SDKOptions options;
    Aws::InitAPI(options);

    Aws::S3::S3Client s3_client;


    Aws::S3::Model::PutObjectRequest object_request;
    object_request.SetBucket(bucketName.c_str());
    object_request.SetKey(keyName.c_str());


    auto input_data = Aws::MakeShared<Aws::FStream>("SampleAllocationTag", encryptedFilePath.c_str(), std::ios_base::in | std::ios_base::binary);
    object_request.SetBody(input_data);


    auto put_object_outcome = s3_client.PutObject(object_request);

    if (put_object_outcome.IsSuccess()) {
        std::cout << "Encrypted file uploaded to S3!" << std::endl;
    } else {
        std::cerr << "Error loading file: " << put_object_outcome.GetError().GetMessage() << std::endl;
    }

    Aws::ShutdownAPI(options);
}

void downloadEncryptedFileFromS3(const std::string& bucketName, const std::string& keyName, const std::string& downloadFilePath) {
    Aws::SDKOptions options;
    Aws::InitAPI(options);

    Aws::S3::S3Client s3_client;

    // request download
    Aws::S3::Model::GetObjectRequest object_request;
    object_request.SetBucket(bucketName.c_str());
    object_request.SetKey(keyName.c_str());

    // download encrypted file
    auto get_object_outcome = s3_client.GetObject(object_request);

    if (get_object_outcome.IsSuccess()) {
        Aws::OFStream local_file;
        local_file.open(downloadFilePath.c_str(), std::ios::out | std::ios::binary);
        local_file << get_object_outcome.GetResult().GetBody().rdbuf();
        std::cout << "Encrypted file loaded to S3" << std::endl;
    } else {
        std::cerr << "Error downloading the file " << get_object_outcome.GetError().GetMessage() << std::endl;
    }

    Aws::ShutdownAPI(options);
}*/