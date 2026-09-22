-- CreateTable
CREATE TABLE "HoneypotEvent" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ip" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "query" TEXT,
    "userAgent" TEXT,
    "headers" JSONB NOT NULL,
    "body" TEXT,
    "route" TEXT,
    "attackType" TEXT,
    "severity" TEXT,
    "analyzed" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "HoneypotEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Report" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "model" TEXT NOT NULL,
    "eventCount" INTEGER NOT NULL,
    "summary" TEXT NOT NULL,
    "breakdown" JSONB NOT NULL,

    CONSTRAINT "Report_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "HoneypotEvent_ip_idx" ON "HoneypotEvent"("ip");

-- CreateIndex
CREATE INDEX "HoneypotEvent_createdAt_idx" ON "HoneypotEvent"("createdAt");

-- CreateIndex
CREATE INDEX "HoneypotEvent_attackType_idx" ON "HoneypotEvent"("attackType");

-- CreateIndex
CREATE INDEX "HoneypotEvent_analyzed_idx" ON "HoneypotEvent"("analyzed");
