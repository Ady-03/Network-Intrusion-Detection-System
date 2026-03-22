-- CreateTable
CREATE TABLE `Topology` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `NetworkNode` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `nodeId` VARCHAR(191) NOT NULL,
    `label` VARCHAR(191) NOT NULL,
    `ip` VARCHAR(191) NOT NULL,
    `type` VARCHAR(191) NOT NULL,
    `x` DOUBLE NOT NULL,
    `y` DOUBLE NOT NULL,
    `topologyId` INTEGER NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `NetworkEdge` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `edgeId` VARCHAR(191) NOT NULL,
    `source` VARCHAR(191) NOT NULL,
    `target` VARCHAR(191) NOT NULL,
    `suspicious` BOOLEAN NOT NULL DEFAULT false,
    `topologyId` INTEGER NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Alert` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `type` VARCHAR(191) NOT NULL,
    `message` TEXT NOT NULL,
    `severity` VARCHAR(191) NOT NULL,
    `srcIp` VARCHAR(191) NOT NULL,
    `dstIp` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `topologyId` INTEGER NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `NetworkNode` ADD CONSTRAINT `NetworkNode_topologyId_fkey` FOREIGN KEY (`topologyId`) REFERENCES `Topology`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `NetworkEdge` ADD CONSTRAINT `NetworkEdge_topologyId_fkey` FOREIGN KEY (`topologyId`) REFERENCES `Topology`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Alert` ADD CONSTRAINT `Alert_topologyId_fkey` FOREIGN KEY (`topologyId`) REFERENCES `Topology`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
